#include "ComScire_R2000KU/qwqng.hpp"

#include <string>
#include <map>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "auth.h"

const char *pid_file = PID_DIR "/server_ComScire_R2000KU.pid";

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void help(void)
{
        printf("-i host   entropy_broker-host to connect to\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -i)\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	char *host = NULL;
	int port = 55225;
	int socket_fd = -1;
	int read_fd = -1;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	int index = 0;
	int verbose = 0;
	char server_type[128];
	bool show_bps = false;
	std::string username, password;

	fprintf(stderr, "eb_server_ComScire_R2000KU v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "hSX:P:o:i:l:snv")) != -1)
	{
		switch(c)
		{
			case 'S':
				show_bps = true;
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'o':
				bytes_file = optarg;
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

			case 'h':
				help();
				return 0;

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

	lock_mem(bytes, sizeof bytes);

	set_logging_parameters(log_console, log_logfile, log_syslog);

	QWQNG *q = QWQNG::Instance();
	if (!q)
		error_exit("Could not find a device? (1)");

	if (!q -> DeviceID())
		error_exit("Could not find a device? (2)");
	lock_mem(q, sizeof *q);

	snprintf(server_type, sizeof(server_type), "server_egb v" VERSION " %s", q -> DeviceID());

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	double cur_start_ts = get_ts();
	long int total_byte_cnt = 0;
	bool stats_error_reported = false;
	for(;;)
	{
		int rc = q -> RandBytes((char *)bytes, 1249);
		if (rc != QNG_S_OK && rc != S_OK)
		{
			if (rc == QNG_E_STATS_EXCEPTION)
			{
				if (!stats_error_reported)
				{
					dolog(LOG_WARNING, "Device reports a statistics test exception");
					stats_error_reported = true;
				}

				usleep(10000); // do not hog cpu

				continue;
			}

			error_exit("Failed to retrieve random bytes from device %x", rc);
		}

		stats_error_reported = false;

		////////

		if (index == sizeof(bytes))
		{
			if (bytes_file)
			{
				emit_buffer_to_file(bytes_file, bytes, index);
			}
			else
			{
				if (message_transmit_entropy_data(host, port, &socket_fd, username, password, server_type, bytes, index) == -1)
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

			total_byte_cnt += 1249;

			if ((now_ts - cur_start_ts) >= 1.0)
			{
				int diff_t = now_ts - cur_start_ts;

				printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, (double)total_byte_cnt / diff_t);

				cur_start_ts = now_ts;
				total_byte_cnt = 0;
			}
		}

		if (index == 0)
		{
			if (socket_fd != -1 && sleep_interruptable(socket_fd, 5) != 0)
			{
				dolog(LOG_INFO, "connection closed");

				close(socket_fd);
				socket_fd = -1;

				continue;
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);

	unlink(pid_file);

	return 0;
}
