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
char *password = NULL;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

int proces_server_msg(int socket_fd)
{
	char msg_cmd[4+1], msg_par[4+1];

	if (READ(socket_fd, msg_cmd, 4) != 4)
	{
		dolog(LOG_INFO, "short read on socket");
		return -1;
	}
	msg_cmd[4] = 0x00;

	if (READ(socket_fd, msg_par, 4) != 4)
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

		if (WRITE(socket_fd, xmit_buffer, 8) != 8)
			return -1;
	}
	else if (strcmp(msg_cmd, "0007") == 0)	/* kernel entropy count */
	{
		char xmit_buffer[128], val_buffer[128];

		snprintf(val_buffer, sizeof(val_buffer), "%d", kernel_rng_get_entropy_count());
		snprintf(xmit_buffer, sizeof(xmit_buffer), "0008%04d%s", (int)strlen(val_buffer), val_buffer);

		dolog(LOG_DEBUG, "Got a kernel entropy count request (with parameter %s), sending reply (%s)", msg_par, xmit_buffer);

		if (WRITE(socket_fd, xmit_buffer, strlen(xmit_buffer)) != strlen(xmit_buffer))
			return -1;
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
	char use_as_is = 0;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
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

	if (!host)
		error_exit("no host to connect to selected");

	set_logging_parameters(log_console, log_logfile, log_syslog);

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

	dolog(LOG_INFO, "started with %d bits in kernel rng", kernel_rng_get_entropy_count());

	if (dev_random_fd == -1)
		error_exit("failed to open %s", DEV_RANDOM);

	for(;;)
	{
		int rc;
		char recv_msg[8 + 1], reply[8 + 1];
		fd_set write_fd;
		fd_set read_fd;

		if (reconnect_server_socket(host, port, password, &socket_fd, argv[0], 0) == -1) // FIXME set client-type
			continue;

		disable_nagle(socket_fd);
		enable_tcp_keepalive(socket_fd);

		// wait for /dev/random te become writable which means the entropy-
		// level dropped below a certain threshold
		FD_ZERO(&write_fd);
		FD_ZERO(&read_fd);
		FD_SET(dev_random_fd, &write_fd);
		FD_SET(socket_fd, &read_fd);

		dolog(LOG_DEBUG, "wait for low-event");
		for(;;)
		{
			int rc = select(max(socket_fd, dev_random_fd) + 1, &read_fd, &write_fd, NULL, NULL); /* wait for krng */
			dolog(LOG_DEBUG, "select returned with %d", rc);
			if (rc >= 0) break;
			if (errno != EINTR && errno != EAGAIN)
				error_exit("Select error: %m");
		}
		dolog(LOG_DEBUG, "back from low-event wait");

		if (FD_ISSET(socket_fd, &read_fd))
		{
			if (proces_server_msg(socket_fd) == -1)
			{
				close(socket_fd);
				socket_fd = -1;
				continue;
			}
		}

		if (FD_ISSET(dev_random_fd, &write_fd))
		{
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
				double seconds = (double)atoi(&reply[4]) + mydrand();

				dolog(LOG_WARNING, "server has no data/quota, sleeping for %f seconds", seconds);

				usleep(seconds * 1000000.0);

				dolog(LOG_DEBUG, "wokeup with %d bits in kernel rng", kernel_rng_get_entropy_count());

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

			if (use_as_is)
				rc = kernel_rng_add_entropy(buffer_out, will_get_n_bytes, will_get_n_bytes * 8);
			else
			{
				int information_n_bits = determine_number_of_bits_of_data(buffer_out, will_get_n_bytes);

				rc = kernel_rng_add_entropy(buffer_out, will_get_n_bytes, information_n_bits);

				dolog(LOG_DEBUG, "%d bits from server contains %d bits of information, new entropy count: %d", will_get_n_bits, information_n_bits, kernel_rng_get_entropy_count());
			}

			if (rc == -1)
				error_exit("error submiting entropy data to kernel");

			free(buffer_out);
			free(buffer_in);
		}
	}

	unlink(pid_file);

	return 0;
}
