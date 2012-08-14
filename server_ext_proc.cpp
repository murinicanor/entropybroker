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
#include <sys/wait.h>

#define SHELL "/bin/bash"

const char *server_type = "server_ext_proc v" VERSION;
const char *pid_file = PID_DIR "/server_ext_proc.pid";
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
	printf("-c command   command to execute\n");
	printf("-S shell  shell to use. default is " SHELL "\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read password from file\n");
}

int main(int argc, char *argv[])
{
	char *host = NULL;
	int port = 55225;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *cmd = NULL, *shell = (char *)SHELL;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "c:S:X:P:o:p:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				password = get_password_from_file(optarg);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'c':
				cmd = optarg;
				break;

			case 'S':
				shell = optarg;
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

	if (!password)
		error_exit("no password set");
	set_password(password);

	if (!host)
		error_exit("no host to connect to given");

	if (!cmd)
		error_exit("no command to execute");

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0600);
	lock_memory();

	set_logging_parameters(log_console, log_logfile, log_syslog);

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
	signal(SIGCHLD, sig_handler);

	bool data = false;
	int socket_fd = -1;
	int got_bytes = -1;
	pid_t child_pid;
	int child_fd = -1;
	char buffer[65536];
	for(;;)
	{
		if (child_fd == -1)
		{
			dolog(LOG_DEBUG, "Starting %s", cmd);

			start_process(shell, cmd, &child_fd, &child_pid);
		}

		// gather random data
		if (!data)
		{
			got_bytes = read(child_fd, buffer, sizeof buffer);
			if (got_bytes <= 0)
			{
				dolog(LOG_DEBUG, "Process stopped");

				close(child_fd);
				child_fd = -1;

				int status = 0;
				wait(&status);

				continue;
			}

			data = true;
		}

		if (data)
		{
			unsigned char *p = (unsigned char *)buffer;
			while(got_bytes > 0)
			{
				int cur_count = min(got_bytes, 1249);

				if (message_transmit_entropy_data(host, port, &socket_fd, password, server_type, p, cur_count) == -1)
				{
					dolog(LOG_INFO, "connection closed");

					close(socket_fd);
					socket_fd = -1;

					break;
				}

				p += cur_count;
				got_bytes -= cur_count;
			}

			data = false;
		}
	}

	unlink(pid_file);

	return 0;
}
