// SVN: $Id$
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>

#include "error.h"
#include "random_source.h"
#include "log.h"
#include "utils.h"
#include "users.h"
#include "auth.h"
#include "kernel_prng_io.h"
#include "server_utils.h"
#include "protocol.h"

int recv_length_data(int fd, char **data, int *len, double to)
{
	char len_buffer[4 + 1] = { 0 };

	if (READ_TO(fd, len_buffer, 4, to) != 4)
		return -1;

	*len = atoi(len_buffer);

	if (*len < 0) // someone is fiddling or something is really wrong
	{
		dolog(LOG_WARNING, "recv_length_data: got negative (%d) length (%s)", *len, len_buffer);
		return -1;
	}
	else if (*len == 0)
		*data = NULL;
	else
	{
		*data = (char *)malloc(*len + 1);

		if (READ_TO(fd, *data, *len, to) != *len)
		{
			free(*data);
			*data = NULL;

			return -1;
		}

		(*data)[*len] = 0x00;
	}

	return 0;
}

int send_length_data(int fd, char *data, int len, double to)
{
	char len_buffer[4 + 1] = { 0 };

	snprintf(len_buffer, sizeof len_buffer, "%04d", len);

	if (WRITE_TO(fd, len_buffer, 4, to) != 4)
		return -1;

	if (len > 0 && WRITE_TO(fd, data, len, to) != len)
		return -1;

	return 0;
}

void make_msg(char *where_to, int code, int value)
{
	if (code < 0 || code > 9999)
		error_exit("invalid code: %d", code);

	if (value < 0)
	{
		dolog(LOG_WARNING, "value %d too small, adjusting to 0", value);
		value = 0;
	}
	else if (value > 9999)
	{
		dolog(LOG_WARNING, "value %d too big, truncating to 9999", value);
		value = 9999;
	}

	snprintf(where_to, 9, "%04d%04d", code, value);
}

void calc_ivec(char *password, long long unsigned int rnd, long long unsigned int counter, unsigned char *dest)
{
	unsigned char *prnd = (unsigned char *)&rnd;
	unsigned char dummy[8] = { 0 };

	memcpy(dummy, password, min(strlen(password), 8));

	// FIXME needs same loop as below
	rnd ^= counter;

	// this loop could be replaced if I were sure what
	// the size of a long is. it is specified to be
	// bigger than an int and at least 64 bit. that
	// would allow 128 (or even bigger) as well
	int index_dummy = 0, index_rnd = 0, rnd_len = sizeof rnd;
	while(index_dummy < 8)
	{
		dummy[index_dummy++] ^= prnd[index_rnd++];

		if (index_rnd == rnd_len)
			index_rnd = 0;
	}

	memcpy(dest, dummy, 8);
}

protocol::protocol(std::vector<std::string> *hosts_in, std::string username_in, std::string password_in, bool is_server_in, std::string type_in, double comm_time_out_in) : hosts(hosts_in), username(username_in), password(password_in), is_server(is_server_in), type(type_in), comm_time_out(comm_time_out_in)
{
	host_index = 0;

        socket_fd = -1;
        sleep_9003 = 300;

        ivec_counter = 0;
	challenge = 13;
        ivec_offset = 0;
}

protocol::~protocol()
{
	if (socket_fd != -1)
		close(socket_fd);
}

void protocol::do_decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes)
{
	BF_cfb64_encrypt(buffer_in, buffer_out, n_bytes, &key, ivec, &ivec_offset, BF_DECRYPT);
}

void protocol::do_encrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes)
{
	BF_cfb64_encrypt(buffer_in, buffer_out, n_bytes, &key, ivec, &ivec_offset, BF_ENCRYPT);
}

void protocol::error_sleep(int count)
{
	long int sleep_micro_seconds = myrand(count * 1000000) + 1;

	dolog(LOG_WARNING, "Failed connecting (%s), sleeping for %f seconds", strerror(errno), double(sleep_micro_seconds) / 1000000.0);

	usleep((long)sleep_micro_seconds);
}

void protocol::set_password(std::string password_in)
{
	int len = password_in.length();

	BF_set_key(&key, len, (unsigned char *)password_in.c_str());
}

void protocol::init_ivec(std::string password_in, long long unsigned int rnd, long long unsigned int counter)
{
	calc_ivec((char *)password_in.c_str(), rnd, counter, ivec);

	ivec_counter = 0;
	ivec_offset = 0;
}

int protocol::reconnect_server_socket()
{
	char connect_msg = 0;
	int count = 1;

	unsigned int host_try_count = 0;
	// connect to server
	if (socket_fd == -1)
	{
		connect_msg = 1;

		for(;;)
		{
			std::string host;
			int port = DEFAULT_BROKER_PORT;
			split_resource_location(hosts -> at(host_index), host, port);

			dolog(LOG_INFO, "Connecting to %s:%d", host.c_str(), port);

			socket_fd = connect_to(host.c_str(), port);
			if (socket_fd != -1)
			{
				if (auth_client_server(socket_fd, 10, username, password, &challenge, is_server, type) == 0)
					break;

				close(socket_fd);
				socket_fd = -1;
			}

			host_index++;
			if (host_index == hosts -> size())
			{
				host_index = 0;

				error_sleep(count);
			}
			else
			{
				dolog(LOG_WARNING, "Failed to connect to %s:%d (%s), continuing with next host", host.c_str(), port, strerror(errno));
			}

			host_try_count++;
			if (host_try_count == hosts -> size())
				dolog(LOG_WARNING, "All hosts are not reachable, still trying");

			if (count < 16)
				count++;
		}

		set_password(password);
		init_ivec(password, challenge, 0);
	}

	if (connect_msg)
		dolog(LOG_INFO, "Connected");

	return 0;
}

int protocol::sleep_interruptable(double how_long)
{
	if (socket_fd == -1)
		return -1;

	int rc = -1;
	fd_set rfds;

	for(;;)
	{
		FD_ZERO(&rfds);
		FD_SET(socket_fd, &rfds);

		struct timeval tv;
		tv.tv_sec = how_long;
		tv.tv_usec = (how_long - double(tv.tv_sec)) * 1000000.0;

		rc = select(socket_fd + 1, &rfds, NULL, NULL, &tv);
		if (rc != -1 || errno != EINTR)
			break;
	}

	if (rc > 0 && FD_ISSET(socket_fd, &rfds))
	{
		char buffer[8 + 1];

		if (READ_TO(socket_fd, buffer, 8, comm_time_out) != 8)
		{
			dolog(LOG_INFO, "error receiving unsollicited message");
			return -1;
		}
		buffer[8] = 0x00;

		if (memcmp(buffer, "0010", 4) == 0)
			dolog(LOG_INFO, "Broker requests for data");
		if (memcmp(buffer, "0009", 4) == 0)
			dolog(LOG_INFO, "Broker informs about data being available");
		else if (memcmp(buffer, "9004", 4) != 0)
			dolog(LOG_WARNING, "Unexpected message '%s' received from broker! (1)", buffer);
		else
			dolog(LOG_WARNING, "Unexpected message '%s' received from broker! (2)", buffer);
	}

	return 0;
}

int protocol::message_transmit_entropy_data(unsigned char *bytes_in, int n_bytes)
{
	if (n_bytes > 1249)
		error_exit("message_transmit_entropy_data: too many bytes %d", n_bytes);

	int error_count = 0;
	for(;;)
	{
		int value;
		char reply[8 + 1] = { 0 };
		char header[8 + 1] = { 0 };

		error_count++;
		if (error_count > MAX_ERROR_SLEEP)
			error_count = MAX_ERROR_SLEEP;

                if (reconnect_server_socket() == -1)
                        continue;

                disable_nagle(socket_fd);
                enable_tcp_keepalive(socket_fd);

		dolog(LOG_DEBUG, "request to send %d bytes", n_bytes);

		if ((n_bytes * 8) > 9999)
			error_exit("internal error: too many bytes to transmit in 1 message (%d)", n_bytes);

		make_msg((char *)header, 2, n_bytes * 8); // 0002 xmit data request

		// header
		if (WRITE_TO(socket_fd, (char *)header, 8, comm_time_out) != 8)
		{
			dolog(LOG_INFO, "error transmitting header");

			close(socket_fd);
			socket_fd = -1;

			error_sleep(error_count);
			continue;
		}

		// ack from server?
	ignore_unsollicited_msg: // we jump to this label when unsollicited msgs are
		// received during data-transmission handshake
		if (READ_TO(socket_fd, reply, 8, comm_time_out) != 8)
		{
			dolog(LOG_INFO, "error receiving ack/nack");

			close(socket_fd);
			socket_fd = -1;

			error_sleep(error_count);
			continue;
		}

		value = atoi(&reply[4]);
		reply[4] = 0x00;

		if (strcmp(reply, "0001") == 0 || strcmp(reply, "9003") == 0)                 // ACK
		{
			int cur_n_bytes = (value + 7) / 8;

			if (cur_n_bytes > n_bytes)
			{
				dolog(LOG_CRIT, "server requesting more data than available");
				return -1;
			}

			dolog(LOG_DEBUG, "Transmitting %d bytes", cur_n_bytes);

			// encrypt data
			int with_hash_n = cur_n_bytes + DATA_HASH_LEN;

			unsigned char *bytes_out = (unsigned char *)malloc(with_hash_n);
			if (!bytes_out)
				error_exit("out of memory");
			unsigned char *temp_buffer = (unsigned char *)malloc(with_hash_n);
			if (!temp_buffer)
				error_exit("out of memory");
			lock_mem(temp_buffer, with_hash_n);

			DATA_HASH_FUNC(bytes_in, cur_n_bytes, temp_buffer);
			memcpy(&temp_buffer[DATA_HASH_LEN], bytes_in, cur_n_bytes);

			do_encrypt(temp_buffer, bytes_out, with_hash_n);

			memset(temp_buffer, 0x00, with_hash_n);
			unlock_mem(temp_buffer, with_hash_n);
			free(temp_buffer);

			if (WRITE_TO(socket_fd, (char *)bytes_out, with_hash_n, comm_time_out) != with_hash_n)
			{
				dolog(LOG_INFO, "error transmitting data");
				free(bytes_out);

				close(socket_fd);
				socket_fd = -1;

				error_sleep(error_count);
				continue;
			}

			free(bytes_out);

			if (strcmp(reply, "9003") == 0)            // ACK but full
			{
				// only usefull for eb_proxy
				dolog(LOG_DEBUG, "pool full, sleeping %d seconds (with ACK)", sleep_9003);
				// same comments as for 9001 apply
				sleep_interruptable(sleep_9003);
			}

			break;
		}
		else if (strcmp(reply, "9001") == 0)            // NACK
		{
			dolog(LOG_DEBUG, "pool full, sleeping %d seconds", value);

			sleep_9003 = (sleep_9003 + value * 2) / 2;

			// now we should sleep and wait for either the time
			// to pass or a 0010 to come in. in reality we just
			// sleep until the first message comes in and then
			// continue; it'll only be 0010 anyway
			sleep_interruptable(value);
		}
		else if (strcmp(reply, "0010") == 0)            // there's a need for data
		{
			// this message can be received during transmission hand-
			// shake as it might have been queued earlier
			goto ignore_unsollicited_msg;
		}
		else if (strcmp(reply, "9004") == 0)            // all pools full, only for provies
			goto ignore_unsollicited_msg;
		else if (strcmp(reply, "0009") == 0)            // got data
			goto ignore_unsollicited_msg;
		else
		{
			dolog(LOG_CRIT, "garbage received: %s", reply);

			error_sleep(error_count);
			continue;
		}

		error_count = 1;
	}

	return 0;
}

int protocol::request_bytes(char *where_to, int n_bits, bool fail_on_no_bits)
{
	bool request_sent = false;

	if (n_bits > 9999 || n_bits <= 0)
		error_exit("Internal error: invalid bit count (%d)", n_bits);

	char request[8 + 1];
	snprintf(request, sizeof request, "0001%04d", n_bits);

	double sleep_trigger = -1;
	int error_count = 0;
	for(;;)
	{
		error_count++;
		if (error_count > MAX_ERROR_SLEEP)
			error_count = MAX_ERROR_SLEEP;

		if (socket_fd == -1)
			request_sent = false;

                if (reconnect_server_socket() == -1)
                        error_exit("Failed to connect");

		if (!request_sent || (sleep_trigger > 0.0 && get_ts() >= sleep_trigger))
		{
			sleep_trigger = -1.0;

			dolog(LOG_DEBUG, "Send request (%s)", request);
			if (WRITE(socket_fd, request, 8) != 8)
			{
				close(socket_fd);
				socket_fd = -1;

				error_sleep(error_count);

				continue;
			}

			request_sent = true;
		}

		char reply[8 + 1];
		int rc = READ_TO(socket_fd, reply, 8, comm_time_out);
		if (rc == 0)
			continue;
		if (rc != 8)
		{
			dolog(LOG_INFO, "Read error, got %d of 8 bytes", rc);

			close(socket_fd);
			socket_fd = -1;

			error_sleep(error_count);

			continue;
		}
		reply[8] = 0x00;

                dolog(LOG_DEBUG, "received reply: %s", reply);

                if (memcmp(reply, "9000", 4) == 0 || memcmp(reply, "9002", 4) == 0) // no data/quota
                {
			error_count = 0;
			int sleep_time = atoi(&reply[4]);
			dolog(LOG_DEBUG, "data denied: %s, sleep for %d seconds", reply[3] == '0' ? "no data" : "quota", sleep_time);

			sleep_trigger = get_ts() + sleep_time;

			if (fail_on_no_bits)
				return 0;
		}
                else if (memcmp(reply, "0004", 4) == 0)       /* ping request */
                {
			error_count = 0;
                        static int pingnr = 0;
                        char xmit_buffer[8 + 1];

                        snprintf(xmit_buffer, sizeof xmit_buffer, "0005%04d", pingnr++);
                        dolog(LOG_DEBUG, "PING");

                        if (WRITE_TO(socket_fd, xmit_buffer, 8, comm_time_out) != 8)
                        {
                                close(socket_fd);
                                socket_fd = -1;
                        }
                }
                else if (memcmp(reply, "0009", 4) == 0)
                {
			error_count = 0;
                        dolog(LOG_INFO, "Broker informs about data");
                }
                else if (memcmp(reply, "0010", 4) == 0)
                {
			error_count = 0;
                        dolog(LOG_INFO, "Broker requests data");
                }
                else if (memcmp(reply, "9004", 4) == 0)
                {
			error_count = 0;
                        dolog(LOG_INFO, "Broker is full");
                }
		else if (memcmp(reply, "0002", 4) == 0)	// there's data!
		{
			error_count = 0;
			int will_get_n_bits = atoi(&reply[4]);
			int will_get_n_bytes = (will_get_n_bits + 7) / 8;

			dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

			if (will_get_n_bytes == 0)
			{
				dolog(LOG_CRIT, "Broker is offering 0 bits?! Please report this to folkert@vanheusden.com");
				request_sent = false;
				continue;
			}

			int xmit_bytes = will_get_n_bytes + DATA_HASH_LEN;
			unsigned char *buffer_in = (unsigned char *)malloc(xmit_bytes);
			if (!buffer_in)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);

			if (READ_TO(socket_fd, (char *)buffer_in, xmit_bytes, comm_time_out) != xmit_bytes)
			{
				dolog(LOG_INFO, "Network read error (data)");

				free(buffer_in);

				close(socket_fd);
				socket_fd = -1;

				request_sent = false;

				continue;
			}

			// decrypt
			unsigned char *temp_buffer = (unsigned char *)malloc(xmit_bytes);
			lock_mem(temp_buffer, will_get_n_bytes);
			do_decrypt(buffer_in, temp_buffer, xmit_bytes);

			// verify data is correct
			unsigned char hash[DATA_HASH_LEN] = { 0 };
			DATA_HASH_FUNC(&temp_buffer[DATA_HASH_LEN], will_get_n_bytes, hash);

			// printf("in  : "); hexdump(temp_buffer, 16);
			// printf("calc: "); hexdump(hash, 16);

			// printf("data: "); hexdump(temp_buffer + DATA_HASH_LEN, 8);

			if (memcmp(hash, temp_buffer, 16) != 0)
				error_exit("Data corrupt!");

			memcpy(where_to, &temp_buffer[DATA_HASH_LEN], will_get_n_bytes);

			memset(temp_buffer, 0x00, xmit_bytes);
			unlock_mem(temp_buffer, xmit_bytes);
			free(temp_buffer);

			free(buffer_in);

			return will_get_n_bytes;
		}
		else
		{
			dolog(LOG_WARNING, "Unknown message %s received (disconnecting)", reply);

			close(socket_fd);
			socket_fd = -1;

			error_sleep(error_count);
		}
	}

	return 0;
}

void protocol::drop()
{
	close(socket_fd);

	socket_fd = -1;
}
