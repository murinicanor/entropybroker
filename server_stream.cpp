#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

const char *server_type = "server_stream v" VERSION;

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"

void help(void)
{
        printf("-i host   eb-host to connect to\n");
	printf("-d dev    device to retrieve from\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	int index = 0;
	char *host = (char *)"127.0.0.1";
	int port = 55225;
	int socket_fd = -1;
	int read_fd = 0; // FIXME: getopt en dan van een file
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *device = NULL;

	printf("%s, (C) 2009 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "i:d:l:sn")) != -1)
	{
		switch(c)
		{
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

			default:
				help();
				return 1;
		}
	}

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	if (device)
		read_fd = open(device, O_RDONLY);
	if (read_fd == -1)
		error_exit("error opening stream");

	signal(SIGPIPE, SIG_IGN);

	for(;;)
	{
		char byte;
		double t1, t2;

		if (reconnect_server_socket(host, port, &socket_fd, server_type) == -1)
			continue;

		// gather random data
		if  (READ(read_fd, &byte, 1) != 1)
			error_exit("error reading from input");

		bytes[index++] = byte;

		if (index == sizeof(bytes))
		{
			if (message_transmit_entropy_data(socket_fd, bytes, index) == -1)
			{
				dolog(LOG_INFO, "connection closed");
				close(socket_fd);
				socket_fd = -1;
				continue;
			}

			index = 0;
		}
	}

	return 0;
}
