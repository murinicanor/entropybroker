#include <string>
#include <map>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <errno.h>
#include <alsa/asoundlib.h>

const char *server_type = "eb_server_audio v" VERSION;
const char *pid_file = PID_DIR "/eb_server_audio.pid";

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "auth.h"

#define DEFAULT_SAMPLE_RATE			11025
#define DEFAULT_CLICK_READ			(1 * DEFAULT_SAMPLE_RATE)
const char *cdevice = "hw:1";				/* capture device */
const char *id = "capture";

#define max(x, y)	((x)>(y)?(x):(y))

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

int setparams(snd_pcm_t *chandle, int sample_rate, snd_pcm_format_t *format)
{
	int err;
	snd_pcm_hw_params_t *ct_params;		/* templates with rate, format and channels */
	snd_pcm_hw_params_alloca(&ct_params);

	err = snd_pcm_hw_params_any(chandle, ct_params);
	if (err < 0)
		error_exit("Broken configuration for %s PCM: no configurations available: %s", id, snd_strerror(err));

	/* Disable rate resampling */
	err = snd_pcm_hw_params_set_rate_resample(chandle, ct_params, 0);
	if (err < 0)
		error_exit("Could not disable rate resampling: %s", snd_strerror(err));

	/* Set access to SND_PCM_ACCESS_RW_INTERLEAVED */
	err = snd_pcm_hw_params_set_access(chandle, ct_params, SND_PCM_ACCESS_RW_INTERLEAVED);
	if (err < 0)
		error_exit("Could not set access to SND_PCM_ACCESS_RW_INTERLEAVED: %s", snd_strerror(err));

	/* Restrict a configuration space to have rate nearest to our target rate */
	err = snd_pcm_hw_params_set_rate_near(chandle, ct_params, (unsigned int *)&sample_rate, 0);
	if (err < 0)
		error_exit("Rate %iHz not available for %s: %s", sample_rate, id, snd_strerror(err));

	/* Set sample format */
	*format = SND_PCM_FORMAT_S16_BE;
	err = snd_pcm_hw_params_set_format(chandle, ct_params, *format);
	if (err < 0)
	{
		*format = SND_PCM_FORMAT_S16_LE;
		err = snd_pcm_hw_params_set_format(chandle, ct_params, *format);
	}
	if (err < 0)
		error_exit("Sample format (SND_PCM_FORMAT_S16_BE and _LE) not available for %s: %s", id, snd_strerror(err));

	/* Set stereo */
	err = snd_pcm_hw_params_set_channels(chandle, ct_params, 2);
	if (err < 0)
		error_exit("Channels count (%i) not available for %s: %s", 2, id, snd_strerror(err));

	/* Apply settings to sound device */
	err = snd_pcm_hw_params(chandle, ct_params);
	if (err < 0)
		error_exit("Could not apply settings to sound device! %s", snd_strerror(err));

	return 0;
}

#define order(a, b)     (((a) == (b)) ? -1 : (((a) > (b)) ? 1 : 0))

void help(void)
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-d dev    audio-device, default %s\n", cdevice);
	printf("-o file   file to write entropy data to (mututal exclusive with -d)\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

void main_loop(char *host, int port, char *bytes_file, char show_bps, std::string username, std::string password)
{
	int n_to_do, bits_out=0, loop;
	char *dummy;
	static short psl=0, psr=0; /* previous samples */
	static char a=1; /* alternater */
	unsigned char byte_out=0;
	int input_buffer_size;
	char *input_buffer;
	snd_pcm_t *chandle;
	snd_pcm_format_t format;
	int err;
	int socket_fd = -1;
	unsigned char bytes[1249]; // 1249 * 8: 9992, must be less then 9999
	int bytes_out = 0;
	double start_ts, cur_start_ts;
	long int total_byte_cnt = 0;

	lock_mem(bytes, sizeof bytes);

	if ((err = snd_pcm_open(&chandle, cdevice, SND_PCM_STREAM_CAPTURE, 0)) < 0)
		error_exit("Record open error: %s", snd_strerror(err));

	/* Open and set up ALSA device for reading */
	setparams(chandle, DEFAULT_SAMPLE_RATE, &format);

	start_ts = get_ts();
	cur_start_ts = start_ts;
	for(;;)
	{
		char got_any = 0;

		input_buffer_size = snd_pcm_frames_to_bytes(chandle, DEFAULT_SAMPLE_RATE * 2);
		input_buffer = (char *)malloc(input_buffer_size);
		if (!input_buffer)
			error_exit("problem allocating %d bytes of memory", input_buffer_size);

		lock_mem(input_buffer, input_buffer_size);

		/* Discard the first data read */
		/* it often contains weird looking data - probably a click from */
		/* driver loading / card initialisation */
		snd_pcm_sframes_t garbage_frames_read = snd_pcm_readi(chandle, input_buffer, DEFAULT_SAMPLE_RATE);
		/* Make sure we aren't hitting a disconnect/suspend case */
		if (garbage_frames_read < 0)
			snd_pcm_recover(chandle, garbage_frames_read, 0);
		/* Nope, something else is wrong. Bail. */
		if (garbage_frames_read < 0)
		{
			dolog(LOG_INFO, "Get random data: read error: %m");

			snd_pcm_close(chandle);

			if ((err = snd_pcm_open(&chandle, cdevice, SND_PCM_STREAM_CAPTURE, 0)) < 0)
				error_exit("Record open error: %s", snd_strerror(err));

			/* Open and set up ALSA device for reading */
			setparams(chandle, DEFAULT_SAMPLE_RATE, &format);
		}

		/* Read a buffer of audio */
		n_to_do = DEFAULT_SAMPLE_RATE * 2;
		dummy = input_buffer;
		while (n_to_do > 0)
		{
			snd_pcm_sframes_t frames_read = snd_pcm_readi(chandle, dummy, n_to_do);
			/* Make	sure we	aren't hitting a disconnect/suspend case */
			if (frames_read < 0)
				frames_read = snd_pcm_recover(chandle, frames_read, 0);
			/* Nope, something else is wrong. Bail.	*/
			if (frames_read < 0)
				error_exit("Read error: %m");
			if (frames_read == -1) 
			{
				if (errno != EINTR)
					error_exit("Read error: %m");
			}
			else
			{
				n_to_do -= frames_read;
				dummy += frames_read;	
			}
		}

		/* de-biase the data */
		for(loop=0; loop<(DEFAULT_SAMPLE_RATE * 2/*16bits*/ * 2/*stereo*/ * 2); loop+=8)
		{
			int w1, w2, w3, w4, o1, o2;

			if (format == SND_PCM_FORMAT_S16_BE)
			{
				w1 = (input_buffer[loop+0]<<8) + input_buffer[loop+1];
				w2 = (input_buffer[loop+2]<<8) + input_buffer[loop+3];
				w3 = (input_buffer[loop+4]<<8) + input_buffer[loop+5];
				w4 = (input_buffer[loop+6]<<8) + input_buffer[loop+7];
			}
			else
			{
				w1 = (input_buffer[loop+1]<<8) + input_buffer[loop+0];
				w2 = (input_buffer[loop+3]<<8) + input_buffer[loop+2];
				w3 = (input_buffer[loop+5]<<8) + input_buffer[loop+4];
				w4 = (input_buffer[loop+7]<<8) + input_buffer[loop+6];
			}

			/* Determine order of channels for each sample, subtract previous sample
			 * to compensate for unbalanced audio devices */
			o1 = order(w1-psl, w2-psr);
			o2 = order(w3-psl, w4-psr);
			if (a > 0)
			{
				psl = w3;
				psr = w4;
			}
			else
			{
				psl = w1;
				psr = w2;
			}

			/* If both samples have the same order, there is bias in the samples, so we
			 * discard them; if both channels are equal on either sample, we discard
			 * them too; additionally, alternate the sample we'll use next (even more
			 * bias removal) */
			if (o1 == o2 || o1 < 0 || o2 < 0)
			{
				a = -a;
			}
			else
			{
				/* We've got a random bit; the bit is either the order from the first or
				 * the second sample, determined by the alternator 'a' */
				char bit = (a > 0) ? o1 : o2;

				byte_out <<= 1;
				byte_out += bit;

				bits_out++;

				got_any = 1;

				if (bits_out>=8)
				{
					bytes[bytes_out++] = byte_out;

					if (bytes_out == sizeof(bytes))
					{
						if (bytes_file)
						{
							emit_buffer_to_file(bytes_file, bytes, bytes_out);
						}
						else if (message_transmit_entropy_data(host, port, &socket_fd, username, password, server_type, bytes, bytes_out) == -1)
						{
							dolog(LOG_INFO, "connection closed");
							close(socket_fd);
							socket_fd = -1;
						}

						bytes_out = 0;
					}

					bits_out = 0;

					if (show_bps)
					{
						double now_ts = get_ts();

						total_byte_cnt++;

						if ((now_ts - cur_start_ts) >= 1.0)
						{
							int diff_t = now_ts - cur_start_ts;

							printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, (double)total_byte_cnt / diff_t);

							total_byte_cnt = 0;
							cur_start_ts = now_ts;
						}
					}
				}
			}
		}

		if (!got_any)
			dolog(LOG_WARNING, "no bits in audio-stream, please make sure the recording channel is not muted");

		memset(input_buffer, 0x00, input_buffer_size);
		unlock_mem(input_buffer, input_buffer_size);
		free(input_buffer);
	}

	unlock_mem(bytes, sizeof bytes);

	snd_pcm_close(chandle);
}

int main(int argc, char *argv[])
{
	char *host = NULL;
	int port = 55225;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "hX:P:So:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'S':
				show_bps = true;
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'd':
				cdevice = optarg;
				break;

			case 'i':
				host = optarg;
				break;

			case 's':
				log_syslog = true;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = true;
				log_console = true;
				break;

			default:
				help();
				return 1;
		}
	}

	if (username.length() == 0 || password.length() == 0)
		error_exit("username + password cannot be empty");
	set_password(password);

	if (!host && !bytes_file)
		error_exit("no host to connect to given");

	if (host != NULL && bytes_file != NULL)
		error_exit("-o and -d are mutual exclusive");

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork && !show_bps)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	main_loop(host, port, bytes_file, show_bps, username, password);

	unlink(pid_file);
}
