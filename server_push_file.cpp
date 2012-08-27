#include <string>
#include <map>
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
#include <openssl/blowfish.h>

const char *server_type = "server_push_file v" VERSION;
const char *pid_file = PID_DIR "/server_push_file.pid";

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "users.h"
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
	printf("-x port   port to connect to (default: %d)\n", DEFAULT_BROKER_PORT);
	printf("-f file   file to read from\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	char *host = NULL;
	int port = DEFAULT_BROKER_PORT;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *file = NULL;
	std::string username, password;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "x:f:hX:P:o:p:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'x':
				port = atoi(optarg);
				if (port < 1)
					error_exit("-x requires a value >= 1");
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
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

	if (!host)
		error_exit("no host to connect to given");

	if (!file)
		error_exit("no file to read from selected");

	(void)umask(0177);
	set_logging_parameters(log_console, log_logfile, log_syslog);

	FILE *fh = fopen(file, "rb");
	if (!fh)
		error_exit("Failed to open file %s", file);

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	no_core();

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	protocol *p = new protocol(host, port, username, password, true, server_type);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	bool data = false;
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
			if (p -> message_transmit_entropy_data(bytes, got_bytes) == -1)
			{
				dolog(LOG_INFO, "connection closed");
				p -> drop();
				continue;
			}

			data = false;
		}
	}

	fclose(fh);

	unlink(pid_file);

	delete p;

	return 0;
}
