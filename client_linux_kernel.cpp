#include <string>
#include <map>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "kernel_prng_io.h"
#include "utils.h"
#include "log.h"
#include "math.h"
#include "protocol.h"
#include "auth.h"

#define DEFAULT_COMM_TO 15
const char *pid_file = PID_DIR "/client_linux_kernel.pid";
const char *client_type = "client_linux_kernel " VERSION;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

int process_server_msg(int socket_fd, bool *data_available)
{
	char msg_cmd[4+1], msg_par[4+1];

	*data_available = false;

	if (READ_TO(socket_fd, msg_cmd, 4, DEFAULT_COMM_TO) != 4)
	{
		dolog(LOG_INFO, "short read on socket");
		return -1;
	}
	msg_cmd[4] = 0x00;

	if (READ_TO(socket_fd, msg_par, 4, DEFAULT_COMM_TO) != 4)
	{
		dolog(LOG_INFO, "short read on socket");
		return -1;
	}
	msg_par[4] = 0x00;

	if (strcmp(msg_cmd, "0004") == 0)	/* ping request */
	{
		static int pingnr = 0;
		char xmit_buffer[8 + 1];

		snprintf(xmit_buffer, sizeof(xmit_buffer), "0005%04d", pingnr++);

		dolog(LOG_DEBUG, "Got a ping request (with parameter %s), sending reply (%s)", msg_par, xmit_buffer);

		if (WRITE_TO(socket_fd, xmit_buffer, 8, DEFAULT_COMM_TO) != 8)
			return -1;
	}
	else if (strcmp(msg_cmd, "0007") == 0)	/* kernel entropy count */
	{
		char xmit_buffer[128], val_buffer[128];

		snprintf(val_buffer, sizeof(val_buffer), "%d", kernel_rng_get_entropy_count());
		snprintf(xmit_buffer, sizeof(xmit_buffer), "0008%04d%s", (int)strlen(val_buffer), val_buffer);

		dolog(LOG_DEBUG, "Got a kernel entropy count request (with parameter %s), sending reply (%s)", msg_par, xmit_buffer);

		if (WRITE_TO(socket_fd, xmit_buffer, strlen(xmit_buffer), DEFAULT_COMM_TO) != (int)strlen(xmit_buffer))
			return -1;
	}
	else if (strcmp(msg_cmd, "0009") == 0)	/* got data */
	{
		*data_available = true;

		dolog(LOG_DEBUG, "Broker signals data available");
	}
	else
	{
		dolog(LOG_CRIT, "Got unknown request: %s", msg_cmd);
		return -1;
	}

	return 0;
}

void help(void)
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	char *host = NULL;
	int port = 55225;
	int socket_fd = -1, dev_random_fd = open(DEV_RANDOM, O_RDWR);
	int max_bits_in_kernel_rng = kernel_rng_get_max_entropy_count();
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	std::string username, password;

	printf("eb_client_linux_kernel v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "X:P:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
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
		error_exit("no host to connect to selected");

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

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0177);
	no_core();

	dolog(LOG_INFO, "started with %d bits in kernel rng", kernel_rng_get_entropy_count());

	if (dev_random_fd == -1)
		error_exit("failed to open %s", DEV_RANDOM);

	bit_count_estimator bce(BCE_SHANNON);

	for(;;)
	{
		fd_set write_fd;
		FD_ZERO(&write_fd);

		// wait for /dev/random te become writable which means the entropy-
		// level dropped below a certain threshold
		FD_SET(dev_random_fd, &write_fd);

		dolog(LOG_DEBUG, "wait for low-event");
		for(;;)
		{
			int rc = select(dev_random_fd + 1, NULL, &write_fd, NULL, NULL);
			if (rc > 0) break;

			if (errno != EINTR && errno != EAGAIN)
				error_exit("Select error: %m");
		}

		int n_bits_in_kernel_rng = kernel_rng_get_entropy_count();
		dolog(LOG_DEBUG, "kernel rng bit count: %d", n_bits_in_kernel_rng);

		if (FD_ISSET(dev_random_fd, &write_fd))
		{
			/* find out how many bits to add */
			int n_bits_to_get = max_bits_in_kernel_rng - n_bits_in_kernel_rng;
			if (n_bits_to_get <= 0)
			{
				dolog(LOG_DEBUG, "number of bits to get <= 0: %d", n_bits_to_get);
				continue;
			}
			if (n_bits_to_get > 9999)
				n_bits_to_get = 9999;

			dolog(LOG_INFO, "%d bits left (%d max), will get %d bits", n_bits_in_kernel_rng, max_bits_in_kernel_rng, n_bits_to_get);

			int n_bytes_to_get = (n_bits_to_get + 7) / 8;

			char *buffer = (char *)malloc(n_bytes_to_get);
			if (!buffer)
				error_exit("out of memory allocating %d bytes", n_bytes_to_get);
			lock_mem(buffer, n_bytes_to_get);

			int n_bytes = request_bytes(&socket_fd, host, port, username, password, client_type, buffer, n_bits_to_get, false);

			int is_n_bits = bce.get_bit_count((unsigned char *)buffer, n_bytes);

			int rc = kernel_rng_add_entropy((unsigned char *)buffer, n_bytes, is_n_bits);
			if (rc == -1)
				error_exit("error submiting entropy data to kernel");

			dolog(LOG_DEBUG, "new entropy count: %d", kernel_rng_get_entropy_count());

			memset(buffer, 0x00, n_bytes_to_get);
			unlock_mem(buffer, n_bytes_to_get);
			free(buffer);
		}
	}

	unlink(pid_file);

	return 0;
}
