#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

const char *server_type = "server_test v" VERSION;

#include "error.h"
#include "utils.h"
#include "log.h"
#include "kernel_prng_io.h"

int main(int argc, char *argv[])
{
	char msg[4+4+1];
	unsigned char bytes[9999/8];
	char *host = (char *)"192.168.64.100";
	int port = 55225;
	int socket_fd = -1;

	signal(SIGPIPE, SIG_IGN);

	kernel_rng_read_non_blocking(bytes, sizeof(bytes));

	for(;;)
	{
		int cur_n_bits = myrand(9992)+1;

		if (reconnect_server_socket(host, port, &socket_fd, server_type) == -1)
			continue;

		if (message_transmit_entropy_data(socket_fd, bytes, (cur_n_bits + 7) / 8) == -1)
		{
			dolog(LOG_INFO, "connection closed");
			close(socket_fd);
			socket_fd = -1;
			continue;
		}
	}

	return 0;
}
