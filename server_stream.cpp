#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

const char *server_type = "server_stream v" VERSION;

#include "error.h"
#include "utils.h"
#include "log.h"

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	int index = 0;
	char *host = (char *)"192.168.64.100";
	int port = 55225;
	int socket_fd = -1;
	int read_fd = 0; // FIXME: getopt en dan van een file

	signal(SIGPIPE, SIG_IGN);

//	printf("timer_entropyd v" VERSION ", (C) 2009 by folkert@vanheusden.com\n\n");

//	if (daemon(-1, -1) == -1)
//		error_exit("failed to become daemon process");

	for(;;)
	{
		char byte;
		double t1, t2;

		if (reconnect_server_socket(host, port, &socket_fd, server_type) == -1)
			continue;

		// gather random data
		if  (READ(read_fd, &byte, 1) != 1)
			error_exit("error reading from input");

		bytes[index++] = byte;

		if (index == sizeof(bytes))
		{
			if (message_transmit_entropy_data(socket_fd, bytes, index) == -1)
			{
				dolog(LOG_INFO, "connection closed");
				close(socket_fd);
				socket_fd = -1;
				continue;
			}

			index = 0;
		}
	}

	return 0;
}
