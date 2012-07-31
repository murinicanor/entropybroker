#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/blowfish.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "auth.h"

#define DEFAULT_COMM_TO 15

unsigned char ivec[8] = { 0 };
BF_KEY key;

void error_sleep(int count)
{
	long int sleep_micro_seconds = myrand(count * 1000000) + 1;

	dolog(LOG_WARNING, "Failed connecting, sleeping for %f seconds", (double)sleep_micro_seconds / 1000000.0);

	usleep((long)sleep_micro_seconds);
}

void set_password(char *password)
{
	int len = strlen(password);

	memcpy(ivec, password, min(len, 8));

	BF_set_key(&key, len, (unsigned char *)password);
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

		set_password(password);
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

int sleep_interruptable(int socket_fd, int how_long)
{
	int rc = -1;
	fd_set rfds;

	for(;;)
	{
		FD_ZERO(&rfds);
		FD_SET(socket_fd, &rfds);

		struct timeval tv;
		tv.tv_sec = how_long;
		tv.tv_usec = myrand(999999);

		rc = select(socket_fd + 1, &rfds, NULL, NULL, &tv);
		if (rc != -1 || errno != EINTR)
			break;
	}

	if (rc > 0 && FD_ISSET(socket_fd, &rfds))
	{
		char buffer[8 + 1];

		if (READ_TO(socket_fd, buffer, 8, DEFAULT_COMM_TO) != DEFAULT_COMM_TO)
		{
			dolog(LOG_INFO, "error receiving unsollicited message");
			return -1;
		}
		buffer[8] = 0x00;

		if (memcmp(buffer, "0010", 4) == 0)
			dolog(LOG_INFO, "Broker requests for data");
		else
			dolog(LOG_WARNING, "Unexpected message '%s' received from broker!", buffer);
	}

	return 0;
}

int message_transmit_entropy_data(int socket_fd, unsigned char *bytes_in, int n_bytes)
{
	for(;;)
	{
		int value;
		char reply[8 + 1] = { 0 };
		char header[8 + 1] = { 0 };

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

			// encrypt data. keep original data; will be used as ivec for next round
			unsigned char *bytes_out = (unsigned char *)malloc(cur_n_bytes);
			if (!bytes_out)
				error_exit("out of memory");
			int num = 0;
			BF_cfb64_encrypt(bytes_in, bytes_out, cur_n_bytes, &key, ivec, &num, BF_ENCRYPT);
			memcpy(ivec, bytes_in, min(8, cur_n_bytes));

			if (WRITE_TO(socket_fd, (char *)bytes_out, cur_n_bytes, DEFAULT_COMM_TO) != cur_n_bytes)
			{
				dolog(LOG_INFO, "error transmitting data");
				free(bytes_out);
				return -1;
			}

			free(bytes_out);

			break;
		}
		else if (strcmp(reply, "9001") == 0)            // NACK
		{
			dolog(LOG_DEBUG, "pool full, sleeping %d seconds", value);

			// now we should sleep and wait for either the time
			// to pass or a 0010 to come in. in reality we just
			// sleep until the first message comes in and then
			// continue; it'll only be 0010 anyway
			sleep_interruptable(socket_fd, value);
		}
		else if (strcmp(reply, "0010") == 0)            // there's a need for data
		{
			dolog(LOG_DEBUG, "Un-expected \"need for data\" message from broker, this is harmless");
		}
		else
		{
			dolog(LOG_CRIT, "garbage received: %s", reply);
			return -1;
		}
	}

	return 0;
}

void decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes)
{
	int num = 0;
	BF_cfb64_encrypt(buffer_in, buffer_out, n_bytes, &key, ivec, &num, BF_DECRYPT);
	memcpy(ivec, buffer_out, min(8, n_bytes));
}
