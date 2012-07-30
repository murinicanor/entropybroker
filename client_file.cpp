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
#include "log.h"
#include "utils.h"
#include "math.h"
#include "protocol.h"
#include "auth.h"
#include "kernel_prng_io.h"

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	exit(0);
}

void help()
{
        printf("-i host   entropy_broker-host to connect to\n");
        printf("-c x      number of bytes to retrieve\n");
        printf("-o file   file to write to\n");
}

int main(int argc, char *argv[])
{
	char *host = (char *)"localhost";
	int port = 55225;
	int socket_fd = -1;
	int c, count = -1;
	char *file = NULL;
	char *password = NULL;

	while((c = getopt(argc, argv, "X:i:o:c:")) != -1)
	{
		switch(c)
		{
			case 'X':
				password = get_password_from_file(optarg);
				break;

			case 'i':
				host = optarg;
				break;

			case 'o':
				file = optarg;
				break;

			case 'c':
				count = atoi(optarg);
				break;

			case 'h':
			default:
				help();
				return 0;
		}
	}

	if (!file)
		error_exit("No outputfile selected");
	if (count < 1)
		error_exit("No byte-count or invalid byte-count (<1) selected");
	if (!password)
		error_exit("No password selected");

	FILE *fh = fopen(file, "wb");
	if (!fh)
		error_exit("Cannot create file %s", file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	while(count > 0)
	{
		char recv_msg[8 + 1] = { 0 }, reply[8 + 1];

		if (reconnect_server_socket(host, port, password, &socket_fd, argv[0], 0) == -1)
			continue;

		disable_nagle(socket_fd);
		enable_tcp_keepalive(socket_fd);

		int n_bytes_to_get = min(1249, count);
		int n_bits_to_get = n_bytes_to_get * 8;
		dolog(LOG_INFO, "will get %d bits", n_bits_to_get);

		snprintf(recv_msg, sizeof(recv_msg), "0001%04d", n_bits_to_get);

		if (WRITE(socket_fd, recv_msg, 8) != 8)
		{
			dolog(LOG_INFO, "write error to %s:%d", host, port);
			close(socket_fd);
			socket_fd = -1;
			continue;
		}

		if (READ(socket_fd, reply, 8) != 8)
		{
			dolog(LOG_INFO, "read error from %s:%d", host, port);
			close(socket_fd);
			socket_fd = -1;
			continue;
		}
		if (memcmp(reply, "0004", 4) == 0)	/* ping request */
		{
			static int pingnr = 0;
			char rreply[8 + 1];

			snprintf(rreply, sizeof(rreply), "0005%04d", pingnr++);

			dolog(LOG_DEBUG, "Got a ping request (with parameter %s), sending reply (%s)", &reply[4], rreply);

			if (WRITE(socket_fd, rreply, 8) != 8)
			{
				dolog(LOG_INFO, "write error to %s:%d", host, port);
				close(socket_fd);
				socket_fd = -1;
			}

			continue;
		}
		else if (memcmp(reply, "0007", 4) == 0)	/* kernel entropy count */
		{
			char xmit_buffer[128], val_buffer[128];

			snprintf(val_buffer, sizeof(val_buffer), "%d", kernel_rng_get_entropy_count());
			snprintf(xmit_buffer, sizeof(xmit_buffer), "0008%04d%s", (int)strlen(val_buffer), val_buffer);

			dolog(LOG_DEBUG, "Got a kernel entropy count request (with parameter %s), sending reply (%s)", reply, xmit_buffer);

			if (WRITE(socket_fd, xmit_buffer, strlen(xmit_buffer)) != (int)strlen(xmit_buffer))
			{
				dolog(LOG_INFO, "write error to %s:%d", host, port);
				close(socket_fd);
				socket_fd = -1;
			}

			continue;
		}
		else if (memcmp(reply, "9000", 4) == 0)
		{
			dolog(LOG_WARNING, "server has no data");
			double seconds = (double)atoi(&reply[4]) + mydrand();
			usleep(seconds * 1000000.0);
			continue;
		}
		if (!(reply[0] == '0' && reply[1] == '0' && reply[2] == '0' && reply[3] == '2'))
			error_exit("invalid msg: %s", reply);
		int will_get_n_bits = atoi(&reply[4]);
		int will_get_n_bytes = (will_get_n_bits + 7) / 8;

		dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

		unsigned char *buffer_in = (unsigned char *)malloc(will_get_n_bytes);
		if (!buffer_in)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);
		unsigned char *buffer_out = (unsigned char *)malloc(will_get_n_bytes);
		if (!buffer_out)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);

		if (READ(socket_fd, (char *)buffer_in, will_get_n_bytes) != will_get_n_bytes)
		{
			dolog(LOG_INFO, "read error from %s:%d", host, port);
			close(socket_fd);
			socket_fd = -1;
			free(buffer_out);
			free(buffer_in);
			continue;
		}

		decrypt(buffer_in, buffer_out, will_get_n_bytes);

		if (fwrite(buffer_out, 1, will_get_n_bytes, fh) != (size_t)will_get_n_bytes)
			error_exit("File write error");

		free(buffer_out);
		free(buffer_in);

		count -= will_get_n_bytes;
	}

	fclose(fh);

	dolog(LOG_INFO, "Finished");

	return 0;
}
