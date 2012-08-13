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

const char *server_type = "server_push_file v" VERSION;
const char *pid_file = PID_DIR "/server_push_file.pid";
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
	printf("-f file   file to read from\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	char *host = NULL;
	int port = 55225;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *file = NULL;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "f:hX:P:o:p:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				password = get_password_from_file(optarg);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'f':
				file = optarg;
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

	if (!host)
		error_exit("no host to connect to given");

	if (!file)
		error_exit("no file to read from selected");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	FILE *fh = fopen(file, "rb");
	if (!fh)
		error_exit("Failed to open file %s", file);

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

	bool data = false;
	int socket_fd = -1;
	int got_bytes = -1;
	for(;!feof(fh);)
	{
		// gather random data
		if (!data)
		{
			got_bytes = fread(bytes, 1, sizeof bytes, fh);
			if (got_bytes <= 0)
				break;

			data = true;
		}

		if (data)
		{
			if (message_transmit_entropy_data(host, port, &socket_fd, password, server_type, bytes, got_bytes) == -1)
			{
				dolog(LOG_INFO, "connection closed");
				close(socket_fd);
				socket_fd = -1;
				continue;
			}

			data = false;
		}
	}

	fclose(fh);

	unlink(pid_file);

	return 0;
}
