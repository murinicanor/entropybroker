#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

const char *server_type = "server_timers v" VERSION;
const char *pid_file = PID_DIR "/server_timers.pid";
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

void help(void)
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read password from file\n");
}

double gen_entropy_data(void)
{
	double start;

	start = get_ts();

	/* arbitrary value:
	 * not too small so that there's room for noise
	 * not too large so that we don't sleep unnecessary
	 */
	usleep(100);

	return get_ts() - start;
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	unsigned char byte;
	int bits = 0, index = 0;
	char *host = NULL;
	int port = 55225;
	int socket_fd = -1;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	char show_bps = 0;
	double start_ts, cur_start_ts;
	long int total_byte_cnt = 0;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "X:P:So:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				password = get_password_from_file(optarg);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'S':
				show_bps = 1;
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'i':
				host = optarg;
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

			default:
				help();
				return 1;
		}
	}

	if (!password)
		error_exit("no password set");
	set_password(password);

	if (!host && !bytes_file && show_bps == 0)
		error_exit("no host to connect to/file to write to given");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork && !show_bps)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	start_ts = get_ts();
	cur_start_ts = start_ts;
	for(;;)
	{
		double t1, t2;

		if (host != NULL)
		{
			if (reconnect_server_socket(host, port, password, &socket_fd, server_type, 1) == -1)
				continue;

			disable_nagle(socket_fd);
			enable_tcp_keepalive(socket_fd);
		}

		// gather random data

		t1 = gen_entropy_data(), t2 = gen_entropy_data();

		if (t1 == t2)
			continue;

		byte <<= 1;
		if (t1 > t2)
			byte |= 1;

		if (++bits == 8)
		{
			bytes[index++] = byte;
			bits = 0;

			if (index == sizeof(bytes))
			{
				if (bytes_file)
				{
					emit_buffer_to_file(bytes_file, bytes, index);
				}
				if (host)
				{
					if (message_transmit_entropy_data(socket_fd, bytes, index) == -1)
					{
						dolog(LOG_INFO, "connection closed");
						close(socket_fd);
						socket_fd = -1;
					}
				}

				index = 0; // skip header
			}

			if (show_bps)
			{
				double now_ts = get_ts();

				total_byte_cnt++;

				if ((now_ts - cur_start_ts) >= 1.0)
				{
					int diff_t = now_ts - start_ts;
					cur_start_ts = now_ts;
					printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, (double)total_byte_cnt / diff_t);
				}
			}
		}
	}

	unlink(pid_file);

	return 0;
}
