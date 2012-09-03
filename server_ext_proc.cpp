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
#include <sys/wait.h>
#include <openssl/blowfish.h>

#define SHELL "/bin/bash"

#define DEFAULT_SLEEP 0

const char *server_type = "server_ext_proc v" VERSION;
const char *pid_file = PID_DIR "/server_ext_proc.pid";

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
	printf("-c command   command to execute\n");
	printf("-Z shell  shell to use. default is " SHELL "\n");
	printf("-b x      how long to sleep between invocations (default: %ds)\n", DEFAULT_SLEEP);
	printf("-o file   file to write entropy data to\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-S        show bps\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	char *host = NULL;
	int port = DEFAULT_BROKER_PORT;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *cmd = NULL, *shell = (char *)SHELL;
	std::string username, password;
	int slp = DEFAULT_SLEEP;
	char *bytes_file = NULL;
	bool show_bps = false;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "So:x:hc:Z:X:P:o:p:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'o':
				bytes_file = optarg;
				break;

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

			case 'c':
				cmd = optarg;
				break;

			case 'S':
				show_bps = true;
				break;

			case 'Z':
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

	if (host && (username.length() == 0 || password.length() == 0))
		error_exit("username + password cannot be empty");

	if (!host && !bytes_file && !show_bps)
		error_exit("no host to connect to, to file to write to and no 'show bps' given");

	if (!cmd)
		error_exit("no command to execute");

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog);

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
	signal(SIGCHLD, SIG_IGN);

	bool data = false;
	int got_bytes = -1;
	pid_t child_pid;
	int child_fd = -1;
	char buffer[32768];
	lock_mem(buffer, sizeof buffer);
	bool first = true;
	double cur_start_ts = get_ts();
	long int total_byte_cnt = 0;
	for(;;)
	{
		if (child_fd == -1)
		{
			if (first)
				first = false;
			else if (sleep > 0)
				sleep(slp);

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
			if (bytes_file)
				emit_buffer_to_file(bytes_file, (unsigned char *)buffer, got_bytes);

			if (show_bps)
			{
				double now_ts = get_ts();

				total_byte_cnt += got_bytes;

				if ((now_ts - cur_start_ts) >= 1.0)
				{
					int diff_t = now_ts - cur_start_ts;

					printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, (double)total_byte_cnt / diff_t);

					total_byte_cnt = 0;
					cur_start_ts = now_ts;
				}
			}

			if (host)
			{
				unsigned char *pnt = (unsigned char *)buffer;
				while(got_bytes > 0)
				{
					int cur_count = min(got_bytes, 1249);

					if (p -> message_transmit_entropy_data(pnt, cur_count) == -1)
					{
						dolog(LOG_INFO, "connection closed");

						p -> drop();
					}

					pnt += cur_count;
					got_bytes -= cur_count;
				}
			}

			data = false;
		}
	}

	unlink(pid_file);

	memset(buffer, 0x00, sizeof buffer);

	delete p;

	return 0;
}
