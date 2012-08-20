#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <openssl/blowfish.h>
#include <openssl/md5.h>
#include <string>
#include <map>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "auth.h"
#include "kernel_prng_io.h"
#include "protocol.h"

#define DEFAULT_COMM_TO 15

unsigned char ivec[8] = { 0 };
long long unsigned ivec_counter = 0, challenge = 13;
int ivec_offset = 0;
BF_KEY key;

static int sleep_9003 = 300;

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

void error_sleep(int count)
{
	long int sleep_micro_seconds = myrand(count * 1000000) + 1;

	dolog(LOG_WARNING, "Failed connecting, sleeping for %f seconds", (double)sleep_micro_seconds / 1000000.0);

	usleep((long)sleep_micro_seconds);
}

void set_password(std::string password)
{
	int len = password.length();

	BF_set_key(&key, len, (unsigned char *)password.c_str());
}

void calc_ivec(char *password, long long unsigned int rnd, long long unsigned int counter, unsigned char *dest)
{
	unsigned char *prnd = (unsigned char *)&rnd;
	unsigned char dummy[8] = { 0 };

	memcpy(dummy, password, min(strlen(password), 8));

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

void init_ivec(std::string password, long long unsigned int rnd, long long unsigned int counter)
{
	calc_ivec((char *)password.c_str(), rnd, counter, ivec);
}

void update_ivec(unsigned char *in, int in_len)
{
	memcpy(ivec, in, min(8, in_len));
}

int reconnect_server_socket(char *host, int port, std::string username, std::string password, int *socket_fd, const char *type, char is_server)
{
	char connect_msg = 0;
	int count = 1;

	for(;;)
	{
		// connect to server
		if (*socket_fd == -1)
		{
			dolog(LOG_INFO, "Connecting to %s:%d", host, port);
			connect_msg = 1;

			for(;;)
			{
				*socket_fd = connect_to(host, port);
				if (*socket_fd != -1)
				{
					if (auth_client_server(*socket_fd, 10, username, password, &challenge) == 0)
						break;

					close(*socket_fd);
					*socket_fd = -1;
				}

				error_sleep(count);

				if (count < 16)
					count++;
			}

			set_password(password);
			init_ivec(password, challenge, 0);
		}

		if (connect_msg)
		{
			char buffer[1250];

			dolog(LOG_INFO, "Connected");

			int len = strlen(type);
			if (len > 1240)
				error_exit("client/server-type too large %d (%s)", len, type);

			if (len == 0)
				error_exit("client/server-type should not be 0 bytes in size");

			if (is_server)
				make_msg((char *)buffer, 3, len);
			else
				make_msg((char *)buffer, 6, len);
			strcat((char *)buffer, type);

			int msg_len = strlen(buffer);

			if (WRITE_TO(*socket_fd, buffer, msg_len, DEFAULT_COMM_TO) != msg_len)
			{
				dolog(LOG_INFO, "connection closed");
				close(*socket_fd);
				*socket_fd = -1;

				error_sleep(count);

				continue;
			}
		}

		break;
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

		if (READ_TO(socket_fd, buffer, 8, DEFAULT_COMM_TO) != 8)
		{
			dolog(LOG_INFO, "error receiving unsollicited message");
			return -1;
		}
		buffer[8] = 0x00;

		if (memcmp(buffer, "0010", 4) == 0)
			dolog(LOG_INFO, "Broker requests for data");
		else if (memcmp(buffer, "9004", 4) != 0)
			dolog(LOG_WARNING, "Unexpected message '%s' received from broker!", buffer);
	}

	return 0;
}

int message_transmit_entropy_data(char *host, int port, int *socket_fd, std::string username, std::string password, const char *server_type, unsigned char *bytes_in, int n_bytes)
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

                if (reconnect_server_socket(host, port, username, password, socket_fd, server_type, 1) == -1)
                        continue;

                disable_nagle(*socket_fd);
                enable_tcp_keepalive(*socket_fd);

		dolog(LOG_DEBUG, "request to send %d bytes", n_bytes);

		if ((n_bytes * 8) > 9999)
			error_exit("internal error: too many bytes to transmit in 1 message (%d)", n_bytes);

		snprintf(header, sizeof(header), "0002%04d", n_bytes * 8);

		// header
		if (WRITE_TO(*socket_fd, (char *)header, 8, DEFAULT_COMM_TO) != 8)
		{
			dolog(LOG_INFO, "error transmitting header");

			close(*socket_fd);
			*socket_fd = -1;

			error_sleep(error_count);
			continue;
		}

		// ack from server?
	ignore_unsollicited_msg: // we jump to this label when unsollicited msgs are
		// received during data-transmission handshake
		if (READ_TO(*socket_fd, reply, 8, DEFAULT_COMM_TO) != 8)
		{
			dolog(LOG_INFO, "error receiving ack/nack");

			close(*socket_fd);
			*socket_fd = -1;

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

			// encrypt data. keep original data; will be used as ivec for next round
			unsigned char *bytes_out = (unsigned char *)malloc(cur_n_bytes);
			if (!bytes_out)
				error_exit("out of memory");
			BF_cfb64_encrypt(bytes_in, bytes_out, cur_n_bytes, &key, ivec, &ivec_offset, BF_ENCRYPT);
			update_ivec(bytes_in, cur_n_bytes);

			int xmit_n = -1;
			insert_hash(&bytes_out, cur_n_bytes, &xmit_n);

			if (WRITE_TO(*socket_fd, (char *)bytes_out, xmit_n, DEFAULT_COMM_TO) != xmit_n)
			{
				dolog(LOG_INFO, "error transmitting data");
				free(bytes_out);
				return -1;
			}

			free(bytes_out);

			if (strcmp(reply, "9003") == 0)            // ACK but full
			{
				// only usefull for eb_proxy
				dolog(LOG_DEBUG, "pool full, sleeping %d seconds (with ACK)", sleep_9003);
				// same comments as for 9001 apply
				sleep_interruptable(*socket_fd, sleep_9003);
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
			sleep_interruptable(*socket_fd, value);
		}
		else if (strcmp(reply, "0010") == 0)            // there's a need for data
		{
			// this message can be received during transmission hand-
			// shake as it might have been queued earlier
			goto ignore_unsollicited_msg;
		}
		else if (strcmp(reply, "9004") == 0)            // all pools full, only for provies
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

void decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes)
{
	BF_cfb64_encrypt(buffer_in, buffer_out, n_bytes, &key, ivec, &ivec_offset, BF_DECRYPT);
	update_ivec(buffer_out, n_bytes);
}

int request_bytes(int *socket_fd, char *host, int port, std::string username, std::string password, const char *client_type, char *where_to, int n_bits, bool fail_on_no_bits)
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

		if (*socket_fd == -1)
			request_sent = false;

                if (reconnect_server_socket(host, port, username, password, socket_fd, client_type, 1) == -1)
                        error_exit("Failed to connect to %s:%d", host, port);

		if (!request_sent || (sleep_trigger > 0.0 && get_ts() >= sleep_trigger))
		{
			sleep_trigger = -1.0;

			dolog(LOG_DEBUG, "Send request (%s)", request);
			if (WRITE(*socket_fd, request, 8) != 8)
			{
				close(*socket_fd);
				*socket_fd = -1;

				error_sleep(error_count);

				continue;
			}

			request_sent = true;
		}

		char reply[8 + 1];
		int rc = READ_TO(*socket_fd, reply, 8, DEFAULT_COMM_TO);
		if (rc == 0)
			continue;
		if (rc != 8)
		{
			dolog(LOG_INFO, "Read error, got %d of 8 bytes", rc);

			close(*socket_fd);
			*socket_fd = -1;

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

                        snprintf(xmit_buffer, sizeof(xmit_buffer), "0005%04d", pingnr++);
                        dolog(LOG_DEBUG, "PING");

                        if (WRITE_TO(*socket_fd, xmit_buffer, 8, DEFAULT_COMM_TO) != 8)
                        {
                                close(*socket_fd);
                                *socket_fd = -1;
                        }
                }
                else if (memcmp(reply, "0007", 4) == 0)  /* kernel entropy count */
                {
			error_count = 0;
                        char xmit_buffer[128], val_buffer[128];

			int entropy_count = kernel_rng_get_entropy_count();
                        snprintf(val_buffer, sizeof(val_buffer), "%d", entropy_count);
                        snprintf(xmit_buffer, sizeof(xmit_buffer), "0008%04d%s", (int)strlen(val_buffer), val_buffer);

                        dolog(LOG_DEBUG, "Send kernel entropy count %d bits", entropy_count);

			int send_len = strlen(xmit_buffer);
                        if (WRITE_TO(*socket_fd, xmit_buffer, send_len, DEFAULT_COMM_TO) != send_len)
                        {
                                close(*socket_fd);
                                *socket_fd = -1;
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

			unsigned char *buffer_in = (unsigned char *)malloc(will_get_n_bytes);
			if (!buffer_in)
				error_exit("out of memory allocating %d bytes", will_get_n_bytes);

			if (READ_TO(*socket_fd, (char *)buffer_in, will_get_n_bytes + MD5_DIGEST_LENGTH, DEFAULT_COMM_TO) != will_get_n_bytes)
			{
				dolog(LOG_INFO, "Network read error (data)");

				free(buffer_in);

				close(*socket_fd);
				*socket_fd = -1;

				request_sent = false;

				continue;
			}

			// decrypt
			int in_len = will_get_n_bytes + MD5_DIGEST_LENGTH;
			unsigned char *temp_buffer = (unsigned char *)malloc(in_len);
			lock_mem(temp_buffer, will_get_n_bytes);
			decrypt(buffer_in, temp_buffer, in_len;

			// verify data is correct
			unsigned char hash[MD5_DIGEST_LENGTH];
			MD5(&temp_buffer[MD5_DIGEST_LENGTH], hash, will_get_n_bytes);

			if (memcmp(hash, temp_buffer, 16) != 0)
				error_exit("Data corrupt!");

			memcpy(where_to, &temp_buffer[MD5_DIGEST_LENGTH], will_get_n_bytes)

			memset(temp_buffer, 0x00, in_len);
			unlock_mem(temp_buffer, in_len);
			free(temp_buffer);

			free(buffer_in);

			return will_get_n_bytes - MD5_DIGEST_LENGTH;
		}
		else
		{
			dolog(LOG_WARNING, "Unknown message %s received", reply);

			close(*socket_fd);
			*socket_fd = -1;

			error_sleep(error_count);
		}
	}

	return 0;
}

void insert_hash(unsigned char **in, int in_len, int *out_len)
{
	unsigned char hash[MD5_DIGEST_LENGTH];
	MD5(in, in_len, hash);

	*out_len = in_len + MD5_DIGEST_LENGTH;
	unsigned char *out = (unsigned char *)malloc(*out_len);

	memcpy(out, hash, MD5_DIGEST_LENGTH);
	memcpy(&out[MD5_DIGEST_LENGTH], *in, in_len);

	free(*in);
	*in = out;
}
