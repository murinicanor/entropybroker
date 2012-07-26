#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "auth.h"

#define DEFAULT_COMM_TO 15

void error_sleep(int count)
{
	long int sleep_micro_seconds = myrand(count * 1000000) + 1;

	dolog(LOG_WARNING, "Failed connecting, sleeping for %f seconds", (double)sleep_micro_seconds / 1000000.0);

	usleep((long)sleep_micro_seconds);
}

int reconnect_server_socket(char *host, int port, char *password, int *socket_fd, const char *type, char is_server)
{
	char connect_msg = 0;

	// connect to server
	if (*socket_fd == -1)
	{
		dolog(LOG_INFO, "Connecting to %s:%d", host, port);
		connect_msg = 1;

		int count = 1;
		for(;;)
		{
			*socket_fd = connect_to(host, port);
			if (*socket_fd != -1)
			{
				if (auth_client_server(*socket_fd, password, 10) == 0)
					break;

				close(*socket_fd);
				*socket_fd = -1;
			}

			error_sleep(count);

			if (count < 16)
				count++;
		}
	}

	if (connect_msg)
	{
		int str_len;
		char buffer[1250];

		dolog(LOG_INFO, "Connected");

		if (strlen(type) == 0)
			error_exit("client/server-type should not be 0 bytes in size");

		if (is_server)
			sprintf((char *)buffer, "0003%04d%s", (int)strlen(type), type);
		else
			sprintf((char *)buffer, "0006%04d%s", (int)strlen(type), type);
		str_len = strlen(buffer);

		if (WRITE_TO(*socket_fd, buffer, str_len, DEFAULT_COMM_TO) != str_len)
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

	dolog(LOG_DEBUG, "request to send %d bytes", n_bytes);

	if ((n_bytes * 8) > 9999)
		error_exit("internal error: too many bytes to transmit in 1 message (%d)", n_bytes);

	snprintf(header, sizeof(header), "0002%04d", n_bytes * 8);

	// header
	if (WRITE_TO(socket_fd, (char *)header, 8, DEFAULT_COMM_TO) != 8)
	{
		dolog(LOG_INFO, "error transmitting header");
		return -1;
	}

	// ack from server?
	if (READ_TO(socket_fd, reply, 8, DEFAULT_COMM_TO) != 8)
	{
		dolog(LOG_INFO, "error receiving ack/nack");
		return -1;
	}

	value = atoi(&reply[4]);
	reply[4] = 0x00;

	if (value <= 0)
	{
		dolog(LOG_CRIT, "%s value %d less then 1", reply, value);
		return -1;
	}

	if (strcmp(reply, "0001") == 0)                 // ACK
	{
		int cur_n_bytes = (value + 7) / 8;

		if (cur_n_bytes > n_bytes)
		{
			dolog(LOG_CRIT, "server requesting more data than available");
			return -1;
		}

		dolog(LOG_DEBUG, "Transmitting %d bytes", cur_n_bytes);

		if (WRITE_TO(socket_fd, (char *)bytes, cur_n_bytes, DEFAULT_COMM_TO) != cur_n_bytes)
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
	{
		dolog(LOG_CRIT, "garbage received: %s", reply);
		return -1;
	}

	return 0;
}
