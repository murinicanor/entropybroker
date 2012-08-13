#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

const char *server_type = "server_stream v" VERSION;
const char *pid_file = PID_DIR "/server_stream.pid";
char *password = NULL;

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "auth.h"

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void split_string(char *in, char split, char ***out, int *n_out)
{
	char *copy_in = strdup(in);

	for(;;)
	{
		char *next;

		(*n_out)++;
		*out = (char **)realloc(*out, *n_out * sizeof(char *));

		(*out)[*n_out - 1] = copy_in;

		next = strchr(copy_in, split);
		if (!next)
			break;

		*next = 0x00;

		copy_in = next + 1;
	}
}

void set_serial_parameters(int fd, char *pars_in)
{
        struct termios newtio;
	char **pars = NULL;
	int n_pars = 0;
	int bps = B9600;
	int bits = CS8;

	split_string(pars_in, ',', &pars, &n_pars);

	// bps,bits
	if (n_pars != 2)
		error_exit("set serial: missing parameter");

	switch(atoi(pars[0]))
	{
		case 50:
			bps = B50;
			break;

		case 75:
			bps = B75;
			break;

		case 110:
			bps = B110;
			break;

		case 134:
			bps = B134;
			break;

		case 150:
			bps = B150;
			break;

		case 200:
			bps = B200;
			break;

		case 300:
			bps = B300;
			break;

		case 600:
			bps = B600;
			break;

		case 1200:
			bps = B1200;
			break;

		case 1800:
			bps = B1800;
			break;

		case 2400:
			bps = B2400;
			break;

		case 4800:
			bps = B4800;
			break;

		case 9600:
			bps = B9600;
			break;

		case 19200:
			bps = B19200;
			break;

		case 38400:
			bps = B38400;
			break;

		case 57600:
			bps = B57600;
			break;

		case 115200:
			bps = B115200;
			break;

		case 230400:
			bps = B230400;
			break;

		case 460800:
			bps = B460800;
			break;

		case 500000:
			bps = B500000;
			break;

		case 576000:
			bps = B576000;
			break;

		case 921600:
			bps = B921600;
			break;

		case 1000000:
			bps = B1000000;
			break;

		case 1152000:
			bps = B1152000;
			break;

		case 1500000:
			bps = B1500000;
			break;

		case 2000000:
			bps = B2000000;
			break;

		case 2500000:
			bps = B2500000;
			break;

		case 3000000:
			bps = B3000000;
			break;

		case 3500000:
			bps = B3500000;
			break;

		case 4000000:
			bps = B4000000;
			break;

		default:
			error_exit("baudrate %s is not understood", pars[0]);
	}

	switch(atoi(pars[1]))
	{
		case 5:
			bits = CS5;
			break;

		case 6:
			bits = CS6;
			break;

		case 7:
			bits = CS7;
			break;

		case 8:
			bits = CS8;
			break;
	}

        if (tcgetattr(fd, &newtio) == -1)
                error_exit("tcgetattr failed");
        newtio.c_iflag = IGNBRK; // | ISTRIP;
        newtio.c_oflag = 0;
        newtio.c_cflag = bps | bits | CREAD | CLOCAL | CSTOPB;
        newtio.c_lflag = 0;
        newtio.c_cc[VMIN] = 1;
        newtio.c_cc[VTIME] = 0;
        tcflush(fd, TCIFLUSH);
        if (tcsetattr(fd, TCSANOW, &newtio) == -1)
                error_exit("tcsetattr failed");
}

void help(void)
{
        printf("-i host   entropy_broker-host to connect to\n");
	printf("-d dev    device to retrieve from\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -d)\n");
	printf("-p pars   if the device is a serial device, then with -p\n");
	printf("          you can set its parameters: bps,bits\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	int index = 0;
	char *host = NULL;
	int port = 55225;
	int socket_fd = -1;
	int read_fd = -1;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *device = NULL;
	char *serial = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "hSX:P:o:p:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'S':
				show_bps = true;
				break;

			case 'X':
				password = get_password_from_file(optarg);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'p':
				serial = optarg;
				break;

			case 'i':
				host = optarg;
				break;

			case 'd':
				device = optarg;
				break;

			case 's':
				log_syslog = 1;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = 1;
				log_console = 1;
				break;

			case 'h':
				help();
				return 0;

			default:
				help();
				return 1;
		}
	}

	if (!password)
		error_exit("no password set");
	set_password(password);

	if (!host && !bytes_file)
		error_exit("no host to connect to given");

	if (host != NULL && bytes_file != NULL)
		error_exit("-o and -d are mutual exclusive");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (device)
		read_fd = open(device, O_RDONLY);
	if (read_fd == -1)
		error_exit("error opening %s", device);

	if (serial)
		set_serial_parameters(read_fd, serial);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	double cur_start_ts = get_ts();
	long int total_byte_cnt = 0;
	for(;;)
	{
		char byte;

		// gather random data
		if  (READ(read_fd, &byte, 1) != 1)
			error_exit("error reading from input");

		bytes[index++] = byte;

		if (index == sizeof(bytes))
		{
			if (bytes_file)
			{
				emit_buffer_to_file(bytes_file, bytes, index);
			}
			else
			{
				if (message_transmit_entropy_data(host, port, &socket_fd, password, server_type, bytes, index) == -1)
				{
					dolog(LOG_INFO, "connection closed");
					close(socket_fd);
					socket_fd = -1;
				}
			}

			index = 0;
		}

		if (show_bps)
		{
			double now_ts = get_ts();

			total_byte_cnt++;

			if ((now_ts - cur_start_ts) >= 1.0)
			{
				int diff_t = now_ts - cur_start_ts;

				printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, double(total_byte_cnt) / diff_t);

				total_byte_cnt = 0;
				cur_start_ts = now_ts;
			}
		}
	}

	unlink(pid_file);

	return 0;
}
