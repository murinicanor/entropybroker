#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "error.h"
#include "log.h"
#include "utils.h"

int reconnect_server_socket(char *host, int port, int *socket_fd, const char *server_type)
{
	char connect_msg = 0;

	// connect to server
	if (*socket_fd == -1)
	{
		dolog(LOG_INFO, "Connecting to %s:%d", host, port);
		connect_msg = 1;
	}

	while(*socket_fd == -1)
	{
		*socket_fd = connect_to(host, port);
		if (*socket_fd == -1)
		{
			long int sleep_micro_seconds = myrand(4000000) + 1;

			dolog(LOG_WARNING, "Failed connecting, sleeping for %f seconds", (double)sleep_micro_seconds / 1000000.0);

			usleep((long)sleep_micro_seconds);
		}
	}

	if (connect_msg)
	{
		int str_len;
		char buffer[1250];

		dolog(LOG_INFO, "Connected");

		sprintf((char *)buffer, "0003%04d%s", (int)(strlen(server_type) * 8), server_type);
		str_len = strlen(buffer);

		if (WRITE(*socket_fd, buffer, str_len) != str_len)
		{
			dolog(LOG_INFO, "connection closed");
			close(*socket_fd);
			*socket_fd = -1;

			return -1;
		}
	}

	return 0;
}

int message_transmit_entropy_data(int socket_fd, unsigned char *bytes, int n_bytes)
{
	int value;
	char reply[8 + 1];
	char header[8 + 1];

	dolog(LOG_DEBUG, "request to send %d bytes", sizeof(bytes) - 8);

	snprintf(header, sizeof(header), "0002%04d", n_bytes * 8);

	// header
	if (WRITE(socket_fd, (char *)header, 8) != 8)
	{
		dolog(LOG_INFO, "error transmitting header");
		return -1;
	}

	// ack from server?
	if (READ(socket_fd, reply, 8) != 8)
	{
		dolog(LOG_INFO, "error receiving ack/nack");
		return -1;
	}

	value = atoi(&reply[4]);
	reply[4] = 0x00;

	if (value <= 0)
		error_exit("value %d less then 1", value);

	if (strcmp(reply, "0001") == 0)                 // ACK
	{
		int cur_n_bytes = (value + 7) / 8;

		if (cur_n_bytes > n_bytes)
			error_exit("server requesting more data than available");

		dolog(LOG_DEBUG, "Transmitting %d bytes", cur_n_bytes);

		if (WRITE(socket_fd, (char *)bytes, cur_n_bytes) != cur_n_bytes)
		{
			dolog(LOG_INFO, "error transmitting data");
			return -1;
		}
	}
	else if (strcmp(reply, "9001") == 0)            // NACK
	{
		dolog(LOG_DEBUG, "pool full, sleeping %d seconds", value);

		sleep(value);
	}
	else
		error_exit("garbage received: %s", reply);

	return 0;
}
