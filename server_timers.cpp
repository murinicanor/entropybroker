#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

const char *server_type = "server_timers v" VERSION;

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"

void help(void)
{
	printf("-i host   eb-host to connect to\n");
	printf("-o file   file to write entropy data to\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
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

	fprintf(stderr, "%s, (C) 2009 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "o:i:l:sn")) != -1)
	{
		switch(c)
		{
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

	if (!host && !bytes_file)
		error_exit("no host to connect to given");

	if (host != NULL && bytes_file != NULL)
		error_exit("-o and -d are mutual exclusive");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	signal(SIGPIPE, SIG_IGN);

	for(;;)
	{
		double t1, t2;

		if (!bytes_file)
		{
			if (reconnect_server_socket(host, port, &socket_fd, server_type, 1) == -1)
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
				else
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
		}
	}

	return 0;
}
