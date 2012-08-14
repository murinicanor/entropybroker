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
char *password = NULL;

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
	printf("-X file   read password from file\n");
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

	printf("eb_client_linux_kernel v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "X:P:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				password = get_password_from_file(optarg);
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

	if (!password)
		error_exit("no password set");

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
	(void)umask(0600);
	lock_memory();

	dolog(LOG_INFO, "started with %d bits in kernel rng", kernel_rng_get_entropy_count());

	if (dev_random_fd == -1)
		error_exit("failed to open %s", DEV_RANDOM);

	bool want_data = false, data_available = false;
	double last_msg = 0.0;
	for(;;)
	{
		bool re_request = false;

		// sometimes tcp sessions fail silently, this code will make
		// this program try at least once every 2 minutes to work
		// around such problems
		double now = get_ts();
		if ((now - last_msg) > TCP_SILENT_FAIL_TEST_INTERVAL)
			re_request = true;

		fd_set read_fd;
		FD_ZERO(&read_fd);
		fd_set write_fd;
		FD_ZERO(&write_fd);

		if (socket_fd == -1)
			re_request = true;

		if (!want_data && !re_request)
		{
			// wait for /dev/random te become writable which means the entropy-
			// level dropped below a certain threshold
			FD_SET(dev_random_fd, &write_fd);
		}

		bool attempt_connect = socket_fd == -1;
		if (reconnect_server_socket(host, port, password, &socket_fd, client_type, 0) == -1)
			continue;
		if (attempt_connect)
			last_msg = get_ts();

		disable_nagle(socket_fd);
		enable_tcp_keepalive(socket_fd);

		if (!re_request)
			FD_SET(socket_fd, &read_fd);

		dolog(LOG_DEBUG, "wait for low-event");
		for(;!re_request;)
		{
			int rc = select(max(socket_fd, dev_random_fd) + 1, &read_fd, &write_fd, NULL, NULL); /* wait for krng */
			dolog(LOG_DEBUG, "select returned with %d", rc);
			if (rc >= 0) break;
			if (errno != EINTR && errno != EAGAIN)
				error_exit("Select error: %m");
		}
		dolog(LOG_DEBUG, "back from low-event wait");
		now = get_ts();

		if (FD_ISSET(socket_fd, &read_fd))
		{
			if (process_server_msg(socket_fd, &data_available) == 0)
				last_msg = now;
			else
			{
				close(socket_fd);
				socket_fd = -1;

				if (!data_available || !want_data)
					continue;
			}
		}

		if (FD_ISSET(dev_random_fd, &write_fd) || (data_available && want_data) || re_request)
		{
			data_available = want_data = false;

			char recv_msg[8 + 1], reply[8 + 1];

			/* find out how many bits to add */
			int n_bits_in_kernel_rng = kernel_rng_get_entropy_count();
			int n_bits_to_get = max_bits_in_kernel_rng - n_bits_in_kernel_rng;
			if (n_bits_to_get <= 0)
			{
				dolog(LOG_DEBUG, "number of bits to get <= 0: %d", n_bits_to_get);
				continue;
			}
			if (n_bits_to_get > 9999)
				n_bits_to_get = 9999;

			dolog(LOG_INFO, "%d bits left (%d max), will get %d bits", n_bits_in_kernel_rng, max_bits_in_kernel_rng, n_bits_to_get);

			snprintf(recv_msg, sizeof(recv_msg), "0001%04d", n_bits_to_get);

			if (WRITE_TO(socket_fd, recv_msg, 8, DEFAULT_COMM_TO) != 8)
			{
				dolog(LOG_INFO, "write error to %s:%d", host, port);
				close(socket_fd);
				socket_fd = -1;
				continue;
			}

			dolog(LOG_DEBUG, "request sent");

			if (READ_TO(socket_fd, reply, 8, DEFAULT_COMM_TO) != 8)
			{
				dolog(LOG_INFO, "read error from %s:%d", host, port);
				close(socket_fd);
				socket_fd = -1;
				continue;
			}
			reply[8] = 0x00;
			dolog(LOG_DEBUG, "received reply: %s", reply);
			if (reply[0] == '9' && reply[1] == '0' && reply[2] == '0' && (reply[3] == '0' || reply[3] == '2'))
			{
				dolog(LOG_WARNING, "server has no data/quota");
				want_data = true;
				continue;
			}
			int will_get_n_bits = atoi(&reply[4]);
			int will_get_n_bytes = (will_get_n_bits + 7) / 8;

			dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

			unsigned char *buffer_in = (unsigned char *)malloc(will_get_n_bytes);
			if (!buffer_in)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);
			unsigned char *buffer_out = (unsigned char *)malloc(will_get_n_bytes);
			if (!buffer_out)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);

			if (READ_TO(socket_fd, (char *)buffer_in, will_get_n_bytes, DEFAULT_COMM_TO) != will_get_n_bytes)
			{
				dolog(LOG_INFO, "read error from %s:%d", host, port);
				free(buffer_in);
				free(buffer_out);
				close(socket_fd);
				socket_fd = -1;
				continue;
			}

			decrypt(buffer_in, buffer_out, will_get_n_bytes);

			dolog(LOG_DEBUG, "data received");

			int rc = kernel_rng_add_entropy(buffer_out, will_get_n_bytes, will_get_n_bits);
			if (rc == -1)
				error_exit("error submiting entropy data to kernel");

			dolog(LOG_DEBUG, "%d bits from server, new entropy count: %d", will_get_n_bits, kernel_rng_get_entropy_count());

			free(buffer_out);
			free(buffer_in);

			last_msg = now;
		}
	}

	unlink(pid_file);

	return 0;
}
