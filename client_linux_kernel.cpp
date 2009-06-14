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

#define DEFAULT_COMM_TO 15

void help(void)
{
        printf("-i host   eb-host to connect to\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
}

int main(int argc, char *argv[])
{
	char *host = (char *)"localhost";
	int port = 55225;
	int socket_fd = -1, dev_random_fd = open(DEV_RANDOM, O_RDWR);
	int max_bits_in_kernel_rng = kernel_rng_get_max_entropy_count();
	char use_as_is = 0;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;

	printf("client_linux_kernel v" VERSION ", (C) 2009 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "i:l:sn")) != -1)
	{
		switch(c)
		{
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

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	signal(SIGPIPE, SIG_IGN);

	dolog(LOG_INFO, "started with %d bits in kernel rng", kernel_rng_get_entropy_count());

	if (dev_random_fd == -1)
		error_exit("failed to open %s", DEV_RANDOM);

	for(;;)
	{
		int rc;
		unsigned char *buffer;
		int will_get_n_bits, will_get_n_bytes;
		char recv_msg[8 + 1], reply[8 + 1];
		int n_bits_in_kernel_rng, n_bits_to_get;
                fd_set write_fd;
                char connect_msg = 0;

		// connect to server
                if (socket_fd == -1)
                {
                        dolog(LOG_INFO, "Connecting to %s:%d", host, port);
                        connect_msg = 1;
                }

                while(socket_fd == -1)
                {
                        socket_fd = connect_to(host, port);
                        if (socket_fd == -1)
                        {
                                long int sleep_micro_seconds = myrand(4000000) + 1;

                                dolog(LOG_WARNING, "Failed connecting, sleeping for %f seconds", (double)sleep_micro_seconds / 1000000.0);

                                usleep((long)sleep_micro_seconds);
                        }
                }

                if (connect_msg)
                        dolog(LOG_INFO, "Connected");

		// wait for /dev/random te become writable which means the entropy-
		// level dropped below a certain threshold
		FD_ZERO(&write_fd);
		FD_SET(dev_random_fd, &write_fd);

		dolog(LOG_DEBUG, "wait for low-event");
		for(;;)
		{
			int rc = select(dev_random_fd+1, NULL, &write_fd, NULL, NULL); /* wait for krng */
			dolog(LOG_DEBUG, "select returned with %d", rc);
			if (rc >= 0) break;
			if (errno != EINTR && errno != EAGAIN)
				error_exit("Select error: %m");
		}
		dolog(LOG_DEBUG, "back from low-event wait");

		/* find out how many bits to add */
		n_bits_in_kernel_rng = kernel_rng_get_entropy_count();
		n_bits_to_get = max_bits_in_kernel_rng - n_bits_in_kernel_rng;
		if (n_bits_to_get <= 0)
			error_exit("number of bits to get <= 0: %d", n_bits_to_get);
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
			double seconds = (double)atoi(&reply[4]) + (double)myrand(1000000)/1000000.0;

			dolog(LOG_WARNING, "server has no data/quota, sleeping for %f seconds", seconds);

			usleep(seconds * 1000000.0);

			dolog(LOG_DEBUG, "wokeup with %d bits in kernel rng", kernel_rng_get_entropy_count());

			continue;
		}
		will_get_n_bits = atoi(&reply[4]);
		will_get_n_bytes = (will_get_n_bits + 7) / 8;

		dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

		buffer = (unsigned char *)malloc(will_get_n_bytes);
		if (!buffer)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);

		if (READ_TO(socket_fd, (char *)buffer, will_get_n_bytes, DEFAULT_COMM_TO) != will_get_n_bytes)
		{
			dolog(LOG_INFO, "read error from %s:%d", host, port);
			close(socket_fd);
			socket_fd = -1;
			continue;
		}

		dolog(LOG_DEBUG, "data received");

		if (use_as_is)
			rc = kernel_rng_add_entropy(buffer, will_get_n_bytes, will_get_n_bytes * 8);
		else
		{
			int information_n_bits = determine_number_of_bits_of_data(buffer, will_get_n_bytes);

			dolog(LOG_DEBUG, "%d bits from server contains %d bits of information", will_get_n_bits, information_n_bits);

			rc = kernel_rng_add_entropy(buffer, will_get_n_bytes, information_n_bits);
		}

		if (rc == -1)
			error_exit("error submiting entropy data to kernel");

		free(buffer);
	}

	return 0;
}
