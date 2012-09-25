// SVN: $Id$
#include <sys/types.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <map>

#include "error.h"
#include "log.h"
#include "math.h"
#include "ivec.h"
#include "hasher.h"
#include "stirrer.h"
#include "pool.h"
#include "fips140.h"
#include "hasher_type.h"
#include "stirrer_type.h"
#include "users.h"
#include "config.h"
#include "scc.h"
#include "pools.h"
#include "utils.h"
#include "signals.h"
#include "auth.h"
#include "protocol.h"
#include "statistics.h"
#include "handle_client.h"
#include "hc_protocol.h"

int send_denied_empty(int fd, statistics *stats, config_t *config)
{
	int seconds = config -> default_sleep_when_pools_empty; // & default_max_sleep_when_pools_empty
	char buffer[4 + 4 + 1];

	stats -> inc_n_times_empty();

	make_msg(buffer, 9000, seconds);

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_quota(int fd, statistics *stats, config_t *config)
{
	char buffer[4 + 4 + 1];

	stats -> inc_n_times_quota();

	make_msg(buffer, 9002, config -> reset_counters_interval); // FIXME daadwerkelijke tijd want die interval kan al eerder getriggered zijn

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_full(int fd, statistics *stats, config_t *config, std::string host)
{
	char buffer[4 + 4 + 1];
	int seconds = config -> default_sleep_time_when_pools_full;

	stats -> inc_n_times_full();

	make_msg(buffer, 9001, seconds);

	dolog(LOG_INFO, "denied|%s all pools full, sleep of %d seconds", host.c_str(), seconds);

	if (WRITE_TO(fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_accepted_while_full(int fd, statistics *stats, config_t *config)
{
	char buffer[4 + 4 + 1];

	make_msg(buffer, 9003, config -> default_sleep_time_when_pools_full);

	if (WRITE_TO(fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_got_data(int fd, pools *ppools, config_t *config)
{
	char buffer[4 + 4 + 1];

	// data is an estimate; it can be different anyway as other clients may come first
	make_msg(buffer, 9, min(9999, ppools -> get_bit_sum(config -> communication_timeout))); // 0009

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_need_data(int fd, config_t *config)
{
	char buffer[4 + 4 + 1];

	make_msg(buffer, 10, 0); // 0010 0000

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int do_proxy_auth(int fd, config_t *config, users *user_map)
{
	char reply[4 + 4 + 1];

	std::string password;
	long long unsigned int challenge;

	// 0012
	if (auth_eb_user(fd, config -> communication_timeout, user_map, password, &challenge, true) == 0)
		make_msg(reply, 12, 0); // 0 == OK
	else
		make_msg(reply, 12, 1); // 1 == FAIL

	return WRITE_TO(fd, reply, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int do_client_get(client_t *client, bool *no_bits)
{
	int cur_n_bits, cur_n_bytes;
	int transmit_size;
	char n_bits[4 + 1];
	n_bits[4] = 0x00;

	*no_bits = false;

	if (READ_TO(client -> socket_fd, n_bits, 4, client -> config -> communication_timeout) != 4)
	{
		dolog(LOG_INFO, "get|%s short read while retrieving number of bits to send", client -> host.c_str());
		return -1;
	}

	cur_n_bits = atoi(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "get|%s 0 bits requested", client -> host.c_str());
		return -1;
	}
	if (cur_n_bits > 9992)
	{
		dolog(LOG_WARNING, "get|%s client requested more than 9992 bits: %d", client -> host.c_str(), cur_n_bits);
		return -1;
	}

	dolog(LOG_DEBUG, "get|%s requested %d bits", client -> host.c_str(), cur_n_bits);

	my_mutex_lock(&client -> stats_lck);
	cur_n_bits = min(cur_n_bits, client -> max_bits_per_interval - client -> bits_sent);
	my_mutex_unlock(&client -> stats_lck);
	dolog(LOG_DEBUG, "get|%s is allowed to now receive %d bits", client -> host.c_str(), cur_n_bits);
	if (cur_n_bits == 0)
		return send_denied_quota(client -> socket_fd, client -> stats, client -> config);
	if (cur_n_bits < 0)
		error_exit("cur_n_bits < 0");

	cur_n_bytes = (cur_n_bits + 7) / 8;

	dolog(LOG_DEBUG, "get|%s memory allocated, retrieving bits", client -> host.c_str());

	unsigned char *temp_buffer = NULL;
	cur_n_bits = client -> ppools -> get_bits_from_pools(cur_n_bits, &temp_buffer, client -> allow_prng, client -> ignore_rngtest_fips140, client -> output_fips140, client -> ignore_rngtest_scc, client -> output_scc, double(client -> config -> communication_timeout) * 0.9);
	if (cur_n_bits == 0)
	{
		dolog(LOG_WARNING, "get|%s no bits in pools, sending deny", client -> host.c_str());
		*no_bits = true;
		return send_denied_empty(client -> socket_fd, client -> stats, client -> config);
	}

	if (cur_n_bits < 0)
		error_exit("internal error: %d < 0", cur_n_bits);
	cur_n_bytes = (cur_n_bits + 7) / 8;
	dolog(LOG_DEBUG, "get|%s got %d bits from pool", client -> host.c_str(), cur_n_bits);

	int out_len = cur_n_bytes + DATA_HASH_LEN;
	unsigned char *ent_buffer_in = (unsigned char *)malloc(out_len);
	lock_mem(ent_buffer_in, out_len);

	memcpy(&ent_buffer_in[DATA_HASH_LEN], temp_buffer, cur_n_bytes);
	memset(ent_buffer_in, 0x00, DATA_HASH_LEN);
	DATA_HASH_FUNC(&ent_buffer_in[DATA_HASH_LEN], cur_n_bytes, ent_buffer_in);

	// printf("send: "); hexdump(ent_buffer_in, 16);
	// printf("data: "); hexdump(ent_buffer_in + DATA_HASH_LEN, 8);

	unsigned char *ent_buffer = (unsigned char *)malloc(out_len);
	if (!ent_buffer)
		error_exit("error allocating %d bytes of memory", out_len);

	// encrypt data
	BF_cfb64_encrypt(ent_buffer_in, ent_buffer, out_len, &client -> key, client -> ivec, &client -> ivec_offset, BF_ENCRYPT);
	// printf("encr: "); hexdump(ent_buffer, 16);

	memset(temp_buffer, 0x00, cur_n_bytes);
	unlock_mem(temp_buffer, cur_n_bytes);
	free(temp_buffer);

	// update statistics for accounting
	my_mutex_lock(&client -> stats_lck);
	client -> bits_sent += cur_n_bits;
	my_mutex_unlock(&client -> stats_lck);

	client -> stats -> track_sents(cur_n_bits);

	transmit_size = 4 + 4 + out_len;
	unsigned char *output_buffer = (unsigned char *)malloc(transmit_size);
	if (!output_buffer)
		error_exit("error allocating %d bytes of memory", cur_n_bytes);
	make_msg((char *)output_buffer, 2, cur_n_bits); // 0002

	dolog(LOG_DEBUG, "get|%s transmit size: %d, msg: %s", client -> host.c_str(), transmit_size, output_buffer);

	memcpy(&output_buffer[8], ent_buffer, out_len);

	free(ent_buffer);

	memset(ent_buffer_in, 0x00, cur_n_bytes);
	unlock_mem(ent_buffer_in, cur_n_bytes);
	free(ent_buffer_in);

	int rc = 0;
	if (WRITE_TO(client -> socket_fd, (char *)output_buffer, transmit_size, client -> config -> communication_timeout) != transmit_size)
	{
		dolog(LOG_INFO, "%s error while sending data to client", client -> host.c_str());

		rc = -1;
	}

	free(output_buffer);

	return rc;
}

int do_client_put(client_t *client, bool *new_bits, bool *is_full)
{
	char msg[4 + 4 + 1];
	int cur_n_bits, cur_n_bytes;
	char n_bits[4 + 1];
	double now = get_ts();
	bool warn_all_full = false;

	*new_bits = false;

	if (client -> ppools -> all_pools_full(double(client -> config -> communication_timeout) * 0.9))
	{
		*is_full = true;

		double last_submit_ago = now - client -> last_put_message;
		char full_allow_interval_submit = last_submit_ago >= client -> config -> when_pools_full_allow_submit_interval;

		if (!(client -> config -> add_entropy_even_if_all_full || full_allow_interval_submit))
		{
			char dummy_buffer[4];

			if (READ_TO(client -> socket_fd, dummy_buffer, 4, client -> config -> communication_timeout) != 4)	// flush number of bits
				return -1;

			return send_denied_full(client -> socket_fd, client -> stats, client -> config, client -> host);
		}

		if (full_allow_interval_submit)
			dolog(LOG_DEBUG, "put|%s(%s) allow submit when full, after %f seconds", client -> host.c_str(), client -> type.c_str(), last_submit_ago);

		warn_all_full = true;
	}

	n_bits[4] = 0x00;

	if (READ_TO(client -> socket_fd, n_bits, 4, client -> config -> communication_timeout) != 4)
	{
		dolog(LOG_INFO, "put|%s(%s) short read while retrieving number of bits to recv", client -> host.c_str(), client -> type.c_str());
		return -1;
	}

	cur_n_bits = atoi(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "put|%s(%s) 0 bits requested", client -> host.c_str(), client -> type.c_str());
		return -1;
	}
	if (cur_n_bits > 9992)
	{
		dolog(LOG_WARNING, "put|%s(%s) client requested more than 9992 bits: %d", client -> host.c_str(), client -> type.c_str(), cur_n_bits);
		return -1;
	}

	if (warn_all_full)
		make_msg(msg, 9003, cur_n_bits);
	else
		make_msg(msg, 1, cur_n_bits); // 0001
	if (WRITE_TO(client -> socket_fd, msg, 8, client -> config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "put|%s short write while sending ack", client -> host.c_str());
		return -1;
	}

	cur_n_bytes = (cur_n_bits + 7) / 8;

	int in_len = cur_n_bytes + DATA_HASH_LEN;
	unsigned char *buffer_in = (unsigned char *)malloc(in_len);
	if (!buffer_in)
		error_exit("%s error allocating %d bytes of memory", client -> host.c_str(), in_len);

	if (READ_TO(client -> socket_fd, (char *)buffer_in, in_len, client -> config -> communication_timeout) != in_len)
	{
		dolog(LOG_INFO, "put|%s short read while retrieving entropy data", client -> host.c_str());

		free(buffer_in);

		return -1;
	}

	unsigned char *buffer_out = (unsigned char *)malloc(in_len);
	if (!buffer_out)
		error_exit("%s error allocating %d bytes of memory", client -> host.c_str(), cur_n_bytes);
	lock_mem(buffer_out, cur_n_bytes);

	// decrypt data
	BF_cfb64_encrypt(buffer_in, buffer_out, in_len, &client -> key, client -> ivec, &client -> ivec_offset, BF_DECRYPT);

	unsigned char *entropy_data = &buffer_out[DATA_HASH_LEN];
	int entropy_data_len = cur_n_bytes;
	unsigned char hash[DATA_HASH_LEN];
	DATA_HASH_FUNC(entropy_data, entropy_data_len, hash);

	if (memcmp(hash, buffer_out, DATA_HASH_LEN) != 0)
		dolog(LOG_WARNING, "Hash mismatch in retrieved entropy data!");
	else
	{
		client -> last_put_message = now;

		int n_bits_added = client -> ppools -> add_bits_to_pools(entropy_data, entropy_data_len, client -> ignore_rngtest_fips140, client -> pfips140, client -> ignore_rngtest_scc, client -> pscc, double(client -> config -> communication_timeout) * 0.9);
		if (n_bits_added == -1)
			dolog(LOG_CRIT, "put|%s error while adding data to pools", client -> host.c_str());
		else
			dolog(LOG_DEBUG, "put|%s %d bits mixed into pools", client -> host.c_str(), n_bits_added);

		my_mutex_lock(&client -> stats_lck);
		client -> bits_recv += n_bits_added;
		my_mutex_unlock(&client -> stats_lck);

		client -> stats -> track_recvs(n_bits_added);

		*new_bits = true;
	}

	memset(buffer_out, 0x00, cur_n_bytes);
	unlock_mem(buffer_out, cur_n_bytes);
	free(buffer_out);

	free(buffer_in);

	return 0;
}

int do_client_server_type(client_t *client)
{
	char *buffer = NULL;
	int n_bytes = 0;

	if (recv_length_data(client -> socket_fd, &buffer, &n_bytes, client -> config -> communication_timeout) == -1)
		return -1;

	if (n_bytes <= 0)
	{
		dolog(LOG_WARNING, "%s sends 0003 msg with 0 bytes of contents", client -> host.c_str());
		return -1;
	}

	client -> type = std::string(buffer);

	dolog(LOG_INFO, "type|%s is \"%s\"", client -> host.c_str(), client -> type.c_str());

	free(buffer);

	return 0;
}

int do_client_kernelpoolfilled_reply(client_t *client)
{
	char *buffer;
	int n_bytes;

	if (recv_length_data(client -> socket_fd, &buffer, &n_bytes, client -> config -> communication_timeout) == -1)
		return -1;

	if (n_bytes <= 0)
	{
		dolog(LOG_WARNING, "%s sends 0008 msg with 0 bytes of contents", client -> host.c_str());
		return -1;
	}

	dolog(LOG_INFO, "kernfill|%s has %d bits", client -> host.c_str(), atoi(buffer));

	free(buffer);

	return 0;
}

int do_client_kernelpoolfilled_request(client_t *client)
{
	char buffer[8 + 1];

	make_msg(buffer, 7, 0); // 0007

	if (WRITE_TO(client -> socket_fd, buffer, 8, client -> config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "kernfill|Short write while sending kernel pool fill status request to %s", client -> host.c_str());
		return -1;
	}

	dolog(LOG_DEBUG, "kernfill|Client kernel pool filled request sent to %s", client -> host.c_str());

	client -> ping_nr++;

	return 0;
}

int do_client(client_t *client, bool *no_bits, bool *new_bits, bool *is_full)
{
	char cmd[4 + 1];
	cmd[4] = 0x00;

	int rc = READ_TO(client -> socket_fd, cmd, 4, client -> config -> communication_timeout);
	if (rc != 4)
	{
		dolog(LOG_INFO, "client|%s short read while retrieving command (%d)", client -> host.c_str(), rc);
		return -1;
	}

	if (strcmp(cmd, "0001") == 0)		// GET bits
	{
		return do_client_get(client, no_bits);
	}
	else if (strcmp(cmd, "0002") == 0)	// PUT bits
	{
		return do_client_put(client, new_bits, is_full);
	}
	else if (strcmp(cmd, "0003") == 0)	// server type
	{
		client -> is_server = true;
		client -> type_set = true;
		return do_client_server_type(client);
	}
	else if (strcmp(cmd, "0006") == 0)	// client type
	{
		// yeah, well, this will fail when threading
		// it does in fact, but I could only reproduce that under valgrind
		client -> is_server = false;
		client -> type_set = true;

		return do_client_server_type(client);
	}
	else if (strcmp(cmd, "0008") == 0)	// # bits in kernel reply (to 0007)
	{
		return do_client_kernelpoolfilled_reply(client);
	}
	else if (strcmp(cmd, "0011") == 0)	// proxy auth
	{
		return do_proxy_auth(client -> socket_fd, client -> config, client -> pu);
	}
	else
	{
		dolog(LOG_INFO, "client|%s command '%s' unknown", client -> host.c_str(), cmd);
		return -1;
	}

	return -1;
}

int notify_server_full(int socket_fd, statistics *stats, config_t *config)
{
	char buffer[8 + 1];

	make_msg(buffer, 9004, 0); // 9004

	if (WRITE_TO(socket_fd, buffer, 8, config -> communication_timeout) != 8)
	{
		stats -> inc_disconnects();

		return -1;
	}

	return 0;
}

int notify_client_data_available(int socket_fd, pools *ppools, statistics *stats, config_t *config)
{
	if (send_got_data(socket_fd, ppools, config) == -1)
	{
		stats -> inc_disconnects();

		return -1;
	}

	return 0;
}

int notify_server_data_needed(int socket_fd, statistics *stats, config_t *config)
{
	if (send_need_data(socket_fd, config) == -1)
	{
		stats -> inc_disconnects();

		return -1;
	}

	return 0;
}
