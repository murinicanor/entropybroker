#include <sys/types.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
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
#include "handle_client.h"
#include "utils.h"
#include "signals.h"
#include "auth.h"
#include "protocol.h"
#include "statistics.h"

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

int send_denied_full(client_t *client, pools *ppools, statistics *stats, config_t *config)
{
	char buffer[4 + 4 + 1];
	int seconds = config -> default_sleep_time_when_pools_full;

	stats -> inc_n_times_full();

	make_msg(buffer, 9001, seconds);

	dolog(LOG_INFO, "denied|%s all pools full, sleep of %d seconds", client -> host, seconds);

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_accepted_while_full(client_t *client, config_t *config)
{
	char buffer[4 + 4 + 1];

	make_msg(buffer, 9003, config -> default_sleep_time_when_pools_full);

	dolog(LOG_INFO, "meta|%s all pools full", client -> host);

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_got_data(int fd, pools *ppools, config_t *config)
{
	char buffer[4 + 4 + 1];

	// data is an estimate; it can be different anyway as other clients may come first
	make_msg(buffer, 9, min(9999, ppools -> get_bit_sum())); // 0009

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_need_data(int fd, config_t *config)
{
	char buffer[4 + 4 + 1];

	make_msg(buffer, 10, 0); // 0010 0000

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int do_proxy_auth(client_t *client, config_t *config, users *user_map)
{
	char reply[4 + 4 + 1];

	std::string password;
	long long unsigned int challenge;

	// 0012
	if (auth_eb_user(client -> socket_fd, config -> communication_timeout, user_map, password, &challenge, true) == 0)
		make_msg(reply, 12, 0); // 0 == OK
	else
		make_msg(reply, 12, 1); // 1 == FAIL

	return WRITE_TO(client -> socket_fd, reply, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int do_client_get(pools *ppools, client_t *client, statistics *stats, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc, bool *no_bits)
{
	int cur_n_bits, cur_n_bytes;
	int transmit_size;
	char n_bits[4 + 1];
	n_bits[4] = 0x00;

	*no_bits = false;

	if (READ_TO(client -> socket_fd, n_bits, 4, config -> communication_timeout) != 4)
	{
		dolog(LOG_INFO, "get|%s short read while retrieving number of bits to send", client -> host);
		return -1;
	}

	cur_n_bits = atoi(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "get|%s 0 bits requested", client -> host);
		return -1;
	}
	if (cur_n_bits > 9992)
	{
		dolog(LOG_WARNING, "get|%s client requested more than 9992 bits: %d", client -> host, cur_n_bits);
		return -1;
	}

	dolog(LOG_DEBUG, "get|%s requested %d bits", client -> host, cur_n_bits);

	pthread_mutex_lock(&client -> stats_lck);
	cur_n_bits = min(cur_n_bits, client -> max_bits_per_interval - client -> bits_sent);
	pthread_mutex_unlock(&client -> stats_lck);
	dolog(LOG_DEBUG, "get|%s is allowed to now receive %d bits", client -> host, cur_n_bits);
	if (cur_n_bits == 0)
		return send_denied_quota(client -> socket_fd, stats, config);
	if (cur_n_bits < 0)
		error_exit("cur_n_bits < 0");

	cur_n_bytes = (cur_n_bits + 7) / 8;

	dolog(LOG_DEBUG, "get|%s memory allocated, retrieving bits", client -> host);

	unsigned char *temp_buffer = NULL;
	cur_n_bits = ppools -> get_bits_from_pools(cur_n_bits, &temp_buffer, client -> allow_prng, client -> ignore_rngtest_fips140, eb_output_fips140, client -> ignore_rngtest_scc, eb_output_scc);
	if (cur_n_bits == 0)
	{
		dolog(LOG_WARNING, "get|%s no bits in pools, sending deny", client -> host);
		*no_bits = true;
		return send_denied_empty(client -> socket_fd, stats, config);
	}

	if (cur_n_bits < 0)
		error_exit("internal error: %d < 0", cur_n_bits);
	cur_n_bytes = (cur_n_bits + 7) / 8;
	dolog(LOG_DEBUG, "get|%s got %d bits from pool", client -> host, cur_n_bits);

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
	pthread_mutex_lock(&client -> stats_lck);
	client -> bits_sent += cur_n_bits;
	pthread_mutex_unlock(&client -> stats_lck);

	stats -> track_sents(cur_n_bits);

	transmit_size = 4 + 4 + out_len;
	unsigned char *output_buffer = (unsigned char *)malloc(transmit_size);
	if (!output_buffer)
		error_exit("error allocating %d bytes of memory", cur_n_bytes);
	make_msg((char *)output_buffer, 2, cur_n_bits); // 0002

	dolog(LOG_DEBUG, "get|%s transmit size: %d, msg: %s", client -> host, transmit_size, output_buffer);

	memcpy(&output_buffer[8], ent_buffer, out_len);

	free(ent_buffer);

	memset(ent_buffer_in, 0x00, cur_n_bytes);
	unlock_mem(ent_buffer_in, cur_n_bytes);
	free(ent_buffer_in);

	int rc = 0;
	if (WRITE_TO(client -> socket_fd, (char *)output_buffer, transmit_size, config -> communication_timeout) != transmit_size)
	{
		dolog(LOG_INFO, "%s error while sending data to client", client -> host);

		rc = -1;
	}

	free(output_buffer);

	return rc;
}

int do_client_put(pools *ppools, client_t *client, statistics *stats, config_t *config, bool *new_bits, bool *is_full)
{
	char msg[4 + 4 + 1];
	int cur_n_bits, cur_n_bytes;
	char n_bits[4 + 1];
	double now = get_ts();
	bool warn_all_full = false;

	*new_bits = false;

	if (ppools -> all_pools_full())
	{
		*is_full = true;

		double last_submit_ago = now - client -> last_put_message;
		char full_allow_interval_submit = last_submit_ago >= config -> when_pools_full_allow_submit_interval;

		if (!(config -> add_entropy_even_if_all_full || full_allow_interval_submit))
		{
			char dummy_buffer[4];

			if (READ_TO(client -> socket_fd, dummy_buffer, 4, config -> communication_timeout) != 4)	// flush number of bits
				return -1;

			return send_denied_full(client, ppools, stats, config);
		}

		if (full_allow_interval_submit)
			dolog(LOG_DEBUG, "put|%s(%s) allow submit when full, after %f seconds", client -> host, client -> type, last_submit_ago);

		warn_all_full = true;
	}

	n_bits[4] = 0x00;

	if (READ_TO(client -> socket_fd, n_bits, 4, config -> communication_timeout) != 4)
	{
		dolog(LOG_INFO, "put|%s(%s) short read while retrieving number of bits to recv", client -> host, client -> type);
		return -1;
	}

	cur_n_bits = atoi(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "put|%s(%s) 0 bits requested", client -> host, client -> type);
		return -1;
	}
	if (cur_n_bits > 9992)
	{
		dolog(LOG_WARNING, "put|%s(%s) client requested more than 9992 bits: %d", client -> host, client -> type, cur_n_bits);
		return -1;
	}

	if (warn_all_full)
		make_msg(msg, 9003, cur_n_bits);
	else
		make_msg(msg, 1, cur_n_bits); // 0001
	if (WRITE_TO(client -> socket_fd, msg, 8, config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "put|%s short write while sending ack", client -> host);
		return -1;
	}

	cur_n_bytes = (cur_n_bits + 7) / 8;

	int in_len = cur_n_bytes + DATA_HASH_LEN;
	unsigned char *buffer_in = (unsigned char *)malloc(in_len);
	if (!buffer_in)
		error_exit("%s error allocating %d bytes of memory", client -> host, in_len);

	if (READ_TO(client -> socket_fd, (char *)buffer_in, in_len, config -> communication_timeout) != in_len)
	{
		dolog(LOG_INFO, "put|%s short read while retrieving entropy data", client -> host);

		free(buffer_in);

		return -1;
	}

	unsigned char *buffer_out = (unsigned char *)malloc(in_len);
	if (!buffer_out)
		error_exit("%s error allocating %d bytes of memory", client -> host, cur_n_bytes);
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

		int n_bits_added = ppools -> add_bits_to_pools(entropy_data, entropy_data_len, client -> ignore_rngtest_fips140, client -> pfips140, client -> ignore_rngtest_scc, client -> pscc);
		if (n_bits_added == -1)
			dolog(LOG_CRIT, "put|%s error while adding data to pools", client -> host);
		else
			dolog(LOG_DEBUG, "put|%s %d bits mixed into pools", client -> host, n_bits_added);

		pthread_mutex_lock(&client -> stats_lck);
		client -> bits_recv += n_bits_added;
		pthread_mutex_unlock(&client -> stats_lck);

		stats -> track_recvs(n_bits_added);

		*new_bits = true;
	}

	memset(buffer_out, 0x00, cur_n_bytes);
	unlock_mem(buffer_out, cur_n_bytes);
	free(buffer_out);

	free(buffer_in);

//	if (warn_all_full)
//		return send_accepted_while_full(client, config);

	return 0;
}

int do_client_server_type(client_t *client, config_t *config)
{
	char *buffer = NULL;
	int n_bytes = 0;

	if (recv_length_data(client -> socket_fd, &buffer, &n_bytes, config -> communication_timeout) == -1)
		return -1;

	if (n_bytes <= 0)
	{
		dolog(LOG_WARNING, "%s sends 0003 msg with 0 bytes of contents", client -> host);
		return -1;
	}

	strncpy(client -> type, buffer, sizeof(client -> type));
	(client -> type)[sizeof(client -> type) - 1] = 0x00;

	dolog(LOG_INFO, "type|%s is \"%s\"", client -> host, client -> type);

	free(buffer);

	return 0;
}

int do_client_kernelpoolfilled_reply(client_t *client, config_t *config)
{
	char *buffer;
	int n_bytes;

	if (recv_length_data(client -> socket_fd, &buffer, &n_bytes, config -> communication_timeout) == -1)
		return -1;

	if (n_bytes <= 0)
	{
		dolog(LOG_WARNING, "%s sends 0008 msg with 0 bytes of contents", client -> host);
		return -1;
	}

	dolog(LOG_INFO, "kernfill|%s has %d bits", client -> host, atoi(buffer));

	free(buffer);

	return 0;
}

int do_client_kernelpoolfilled_request(client_t *client, config_t *config)
{
	char buffer[8 + 1];

	make_msg(buffer, 7, 0); // 0007

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "kernfill|Short write while sending kernel pool fill status request to %s", client -> host);
		return -1;
	}

	dolog(LOG_DEBUG, "kernfill|Client kernel pool filled request sent to %s", client -> host);

	client -> ping_nr++;

	return 0;
}
