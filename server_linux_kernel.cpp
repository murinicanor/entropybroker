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
#include <openssl/blowfish.h>

const char *server_type = "server_kernel v" VERSION;
const char *pid_file = PID_DIR "/server_kernel.pid";

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "users.h"
#include "auth.h"
#include "kernel_prng_io.h"
#include "kernel_prng_rw.h"

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
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
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
	char *bytes_file = NULL;
	bool show_bps = false;
	long int total_byte_cnt = 0;
	std::string username, password;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);
	printf("Please note: this program RETRIEVES entropy data from the kernel and feeds that to the entropybroker!\n");
	printf("If you want to ADD data to the kernel entropy buffer instead (which is what you most likely want to do), then use eb_client_linux_kernel\n");

	while((c = getopt(argc, argv, "x:hX:P:So:i:l:sn")) != -1)
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

			case 'S':
				show_bps = true;
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

			default:
				help();
				return 1;
		}
	}

	if (host && (username.length() == 0 || password.length() == 0))
		error_exit("username + password cannot be empty");

	if (!host && !bytes_file && !show_bps)
		error_exit("no host to connect to, to file to write to and no 'show bps' given");

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

	protocol *p = NULL;
	if (host)
		p = new protocol(host, port, username, password, true, server_type);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	unsigned char bytes[1249];
	lock_mem(bytes, sizeof bytes);

	double cur_start_ts = get_ts();
	for(;;)
	{
		dolog(LOG_DEBUG, "Bits available: %d", kernel_rng_get_entropy_count());

		if (kernel_rng_read_blocking(bytes, sizeof bytes) == -1)
		{
			dolog(LOG_WARNING, "Problem reading from kernel entropy buffer!");

			if (p != NULL && p -> sleep_interruptable(5) != 0)
			{
				dolog(LOG_INFO, "connection closed");
				p -> drop();
				continue;
			}
		}

		if (bytes_file)
			emit_buffer_to_file(bytes_file, bytes, sizeof bytes);

		if (host && p -> message_transmit_entropy_data(bytes, sizeof bytes) == -1)
		{
			dolog(LOG_INFO, "connection closed");
			p -> drop();
			continue;
		}

		if (show_bps)
		{
			double now_ts = get_ts();

			total_byte_cnt += sizeof bytes;

			if ((now_ts - cur_start_ts) >= 1.0)
			{
				int diff_t = now_ts - cur_start_ts;

				printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, double(total_byte_cnt) / diff_t);

				cur_start_ts = now_ts;
				total_byte_cnt = 0;
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
