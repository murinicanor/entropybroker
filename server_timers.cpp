#include <string>
#include <map>
#include <vector>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/blowfish.h>

const char *server_type = "server_timers v" VERSION;
const char *pid_file = PID_DIR "/server_timers.pid";

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "users.h"
#include "auth.h"

#define SLEEP_CLOCK	CLOCK_MONOTONIC

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void help(void)
{
        printf("-I host   entropy_broker host to connect to\n");
        printf("          e.g. host\n");
        printf("               host:port\n");
        printf("               [ipv6 literal]:port\n");
        printf("          you can have multiple entries of this\n");
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int get_clock_res()
{
	struct timespec ts;

	if (clock_getres(SLEEP_CLOCK, &ts) == -1)
		error_exit("clock_getres failed");

	return ts.tv_nsec;
}

inline double gen_entropy_data(int sl)
{
	double start = get_ts_ns();

	const struct timespec ts = { 0, sl };
	clock_nanosleep(SLEEP_CLOCK, 0, &ts, NULL);

	return get_ts_ns() - start;
}


int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	unsigned char byte = 0;
	int bits = 0, index = 0;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;
	std::vector<std::string> hosts;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "I:hX:P:So:l:sn")) != -1)
	{
		switch(c)
		{
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

			case 'I':
				hosts.push_back(optarg);
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

	if (hosts.size() > 0 && (username.length() == 0 || password.length() == 0))
		error_exit("username + password cannot be empty");

	if (hosts.size() == 0 && !bytes_file)
		error_exit("no host to connect to or file to write to given");

	(void)umask(0177);
	no_core();
	lock_mem(bytes, sizeof bytes);

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork && !show_bps)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	protocol *p = NULL;
	if (hosts.size() > 0)
		p = new protocol(&hosts, username, password, true, server_type);

	int slp = get_clock_res();
	dolog(LOG_INFO, "resolution of clock is %dns", slp);

	init_showbps();
	set_showbps_start_ts();

	int equal_cnt = 0;
	for(;;)
	{
		// gather random data
		double t1 = gen_entropy_data(slp), t2 = gen_entropy_data(slp);

		if (t1 == t2)
		{
			equal_cnt++;

			if (equal_cnt > 5 && slp < 1000)
			{
				dolog(LOG_DEBUG, "increasing sleep to %dns", slp);

				slp++;
			}

			continue;
		}
		equal_cnt = 0;

		byte <<= 1;
		if (t1 >= t2)
			byte |= 1;

		if (++bits == 8)
		{
			bytes[index++] = byte;
			bits = 0;

			if (index == sizeof bytes)
			{
				if (show_bps)
					update_showbps(sizeof bytes);

				if (bytes_file)
					emit_buffer_to_file(bytes_file, bytes, index);

				if (p && p -> message_transmit_entropy_data(bytes, index) == -1)
				{
					dolog(LOG_INFO, "connection closed");

					p -> drop();
				}

				set_showbps_start_ts();

				index = 0; // skip header
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
