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

int main(int argc, char *argv[])
{
	char *host = (char *)"192.168.64.100";
	int port = 55225;
	int socket_fd = -1;

	signal(SIGPIPE, SIG_IGN);

	for(;;)
	{
		unsigned char *buffer;
		int will_get_n_bits, will_get_n_bytes;
		char recv_msg[8 + 1], reply[8 + 1];
		int n_bits_to_get;
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

		disable_nagle(socket_fd);
		enable_tcp_keepalive(socket_fd);

		n_bits_to_get = myrand(9992) + 1;
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
		reply[8] = 0x00;
		if (strcmp(reply, "90000000") == 0)
		{
			dolog(LOG_WARNING, "server has no data");
			continue;
		}
		if (!(reply[0] == '0' && reply[1] == '0' && reply[2] == '0' && reply[3] == '2'))
			error_exit("invalid msg: %s", reply);
		will_get_n_bits = atoi(&reply[4]);
		will_get_n_bytes = (will_get_n_bits + 7) / 8;

		dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

		buffer = (unsigned char *)malloc(will_get_n_bytes);
		if (!buffer)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);

		if (READ(socket_fd, (char *)buffer, will_get_n_bytes) != will_get_n_bytes)
		{
			dolog(LOG_INFO, "read error from %s:%d", host, port);
			close(socket_fd);
			socket_fd = -1;
			continue;
		}

		free(buffer);
	}

	return 0;
}
