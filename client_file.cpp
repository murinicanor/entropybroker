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
#include <signal.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "math.h"
#include "protocol.h"
#include "auth.h"
#include "kernel_prng_io.h"

#define DEFAULT_COMM_TO 15
const char *pid_file = PID_DIR "/client_egd.pid";
char *password = NULL;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void help(void)
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-c count  number of BYTES\n");
	printf("-f file   write bytes to \"file\"\n");
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
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	int count = 0;
	char *file = NULL;

	printf("eb_client_file v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "c:f:X:P:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'c':
				count = atoi(optarg);
				break;

			case 'f':
				file = optarg;
				break;

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
		error_exit("No password set");

	if (!host)
		error_exit("No host to connect to selected");

	if (!file)
		error_exit("No file to write to selected");

	if (count < 1)
		error_exit("Count must be >= 1");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	int socket_fd = -1;

	FILE *fh = fopen(file, "wb");
	if (!fh)
		error_exit("Failed to create file %s", file);

	while(count > 0)
	{
		char get_msg[8 + 1], reply[8 + 1];
		int n_bytes_to_get = min(count, 1249);
		int n_bits_to_get = n_bytes_to_get * 8;

		dolog(LOG_INFO, "will get %d bits", n_bits_to_get);
		snprintf(get_msg, sizeof(get_msg), "0001%04d", n_bits_to_get);

		bool send_request = true;
		double last_msg = 0.0;
		for(;;)
		{
			double now = get_ts();
			if ((now - last_msg) > TCP_SILENT_FAIL_TEST_INTERVAL)
				send_request = true;

			if (socket_fd == -1)
			{
				dolog(LOG_INFO, "(re-)connecting to %s:%d", host, port);

				send_request = true;
				if (reconnect_server_socket(host, port, password, &socket_fd, "client_file " VERSION, 0) == -1)
				{
					dolog(LOG_CRIT, "cannot connect to %s:%d", host, port);
					continue;
				}

				now = get_ts();
				last_msg = now;

				dolog(LOG_INFO, "Connected, fd: %d", socket_fd);
			}

			if (send_request)
			{
				dolog(LOG_DEBUG, "Request for %d bits", n_bits_to_get);

				if (WRITE_TO(socket_fd, get_msg, 8, DEFAULT_COMM_TO) != 8)
				{
					dolog(LOG_INFO, "write error to %s:%d", host, port);
					close(socket_fd);
					socket_fd = -1;
					send_request = true;
					continue;
				}

				last_msg = now;
			}

			dolog(LOG_DEBUG, "request sent");

			double sleep = (last_msg + TCP_SILENT_FAIL_TEST_INTERVAL) - now;
			if (sleep <= 0.0)
				sleep = 1.0;

			int rc = READ_TO(socket_fd, reply, 8, send_request ? DEFAULT_COMM_TO : sleep);
			if (rc == 0)
				send_request = true;
			else if (rc != 8)
			{
				dolog(LOG_INFO, "read error from %s:%d", host, port);
				close(socket_fd);
				socket_fd = -1;
				send_request = true;
				continue;
			}
			reply[8] = 0x00;

			dolog(LOG_DEBUG, "received reply: %s", reply);

			if (memcmp(reply, "9000", 4) == 0 || memcmp(reply, "9002", 4) == 0)
			{
				dolog(LOG_WARNING, "server has no data/quota");

				send_request = false;
				continue;
			}
			else if (memcmp(reply, "0004", 4) == 0)       /* ping request */
			{
				static int pingnr = 0;
				char xmit_buffer[8 + 1];

				snprintf(xmit_buffer, sizeof(xmit_buffer), "0005%04d", pingnr++);

				dolog(LOG_DEBUG, "PING");

				if (WRITE_TO(socket_fd, xmit_buffer, 8, DEFAULT_COMM_TO) != 8)
				{
					close(socket_fd);
					socket_fd = -1;
				}

				send_request = true;
				continue;
			}
			else if (memcmp(reply, "0007", 4) == 0)  /* kernel entropy count */
			{
				char xmit_buffer[128], val_buffer[128];

				snprintf(val_buffer, sizeof(val_buffer), "%d", kernel_rng_get_entropy_count());
				snprintf(xmit_buffer, sizeof(xmit_buffer), "0008%04d%s", (int)strlen(val_buffer), val_buffer);

				dolog(LOG_DEBUG, "Send kernel entropy count");

				if (WRITE_TO(socket_fd, xmit_buffer, strlen(xmit_buffer), DEFAULT_COMM_TO) != (int)strlen(xmit_buffer))
				{
					close(socket_fd);
					socket_fd = -1;
				}

				send_request = true;
				continue;
			}
			else if (memcmp(reply, "0009", 4) == 0)
			{
				// broker has data!
				dolog(LOG_INFO, "Broker informs about data");

				send_request = true;
				continue;
			}

			int will_get_n_bits = atoi(&reply[4]);
			int will_get_n_bytes = (will_get_n_bits + 7) / 8;

			dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

			if (will_get_n_bytes == 0)
			{
				dolog(LOG_CRIT, "Broker is offering 0 bits?! Please report this to folkert@vanheusden.com");
				send_request = true;
				continue;
			}

			unsigned char *buffer_in = (unsigned char *)malloc(will_get_n_bytes);
			if (!buffer_in)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);
			unsigned char *buffer_out = (unsigned char *)malloc(will_get_n_bytes);
			if (!buffer_out)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);

			if (READ_TO(socket_fd, (char *)buffer_in, will_get_n_bytes, DEFAULT_COMM_TO) != will_get_n_bytes)
			{
				dolog(LOG_INFO, "read error from %s:%d", host, port);

				free(buffer_out);
				free(buffer_in);

				close(socket_fd);
				socket_fd = -1;

				send_request = true;
				continue;
			}
			else
			{
				decrypt(buffer_in, buffer_out, will_get_n_bytes);

				if (fwrite(buffer_out, 1, will_get_n_bytes, fh) != (size_t)will_get_n_bytes)
					error_exit("Failed to write to file");
			}

			free(buffer_out);
			free(buffer_in);

			count -= will_get_n_bytes;

			break;
		}
	}

	close(socket_fd);
	fclose(fh);

	unlink(pid_file);

	dolog(LOG_INFO, "Finished");

	return 0;
}
