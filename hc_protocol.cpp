// SVN: $Revision$
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <map>
#include <stdio.h>

#include "error.h"
#include "random_source.h"
#include "log.h"
#include "math.h"
#include "hasher.h"
#include "stirrer.h"
#include "fips140.h"
#include "hasher_type.h"
#include "stirrer_type.h"
#include "pool_crypto.h"
#include "pool.h"
#include "users.h"
#include "encrypt_stream.h"
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
	unsigned char buffer[4 + 4];

	stats -> inc_n_times_empty();

	make_msg(buffer, 9000, seconds);

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_quota(int fd, statistics *stats, config_t *config)
{
	unsigned char buffer[4 + 4];

	stats -> inc_n_times_quota();

	make_msg(buffer, 9002, config -> reset_counters_interval); // FIXME daadwerkelijke tijd want die interval kan al eerder getriggered zijn

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_full(int fd, statistics *stats, config_t *config, std::string host)
{
	unsigned char buffer[4 + 4];
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
	unsigned char buffer[4 + 4];

	make_msg(buffer, 9003, config -> default_sleep_time_when_pools_full);

	if (WRITE_TO(fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_got_data(int fd, pools *ppools, config_t *config)
{
	unsigned char buffer[4 + 4];

	// data is an estimate; it can be different anyway as other clients may come first
	make_msg(buffer, 9, mymin(9999, ppools -> get_bit_sum(config -> communication_timeout))); // 0009

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_need_data(int fd, config_t *config)
{
	unsigned char buffer[4 + 4];

	make_msg(buffer, 10, 0); // 0010 0000

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int do_client_get(client_t *client, bool *no_bits)
{
	int transmit_size;
	unsigned char n_bits[4];

	*no_bits = false;

	if (READ_TO(client -> socket_fd, n_bits, 4, client -> config -> communication_timeout) != 4)
	{
		dolog(LOG_INFO, "get|%s short read while retrieving number of bits to send", client -> host.c_str());
		return -1;
	}

	int cur_n_bits = uchar_to_uint(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "get|%s 0 bits requested", client -> host.c_str());
		return -1;
	}
	if (cur_n_bits > client -> config -> max_get_put_size)
	{
		dolog(LOG_WARNING, "get|%s client requested more than %d bits: %d", client -> host.c_str(), client -> config -> max_get_put_size, cur_n_bits);
		return -1;
	}

	dolog(LOG_DEBUG, "get|%s requested %d bits", client -> host.c_str(), cur_n_bits);

	my_mutex_lock(&client -> stats_lck);
	cur_n_bits = mymin(cur_n_bits, client -> max_bits_per_interval - client -> bits_sent);
	my_mutex_unlock(&client -> stats_lck);
	dolog(LOG_DEBUG, "get|%s is allowed to now receive %d bits", client -> host.c_str(), cur_n_bits);
	if (cur_n_bits == 0)
	{
		client -> stats_user -> inc_n_times_quota();
		return send_denied_quota(client -> socket_fd, client -> stats_glob, client -> config);
	}
	if (cur_n_bits < 0)
		error_exit("cur_n_bits < 0");

	int cur_n_bytes = (cur_n_bits + 7) / 8;

	dolog(LOG_DEBUG, "get|%s memory allocated, retrieving bits", client -> host.c_str());

	unsigned char *temp_buffer = NULL;
	cur_n_bits = client -> ppools -> get_bits_from_pools(cur_n_bits, &temp_buffer, client -> allow_prng, client -> ignore_rngtest_fips140, client -> output_fips140, client -> ignore_rngtest_scc, client -> output_scc, double(client -> config -> communication_timeout) * 0.9, client -> pc);
	if (cur_n_bits == 0)
	{
		free_locked(temp_buffer, cur_n_bytes + 1);

		dolog(LOG_WARNING, "get|%s no bits in pools, sending deny", client -> host.c_str());
		*no_bits = true;
		client -> stats_user -> inc_n_times_empty();
		return send_denied_empty(client -> socket_fd, client -> stats_glob, client -> config);
	}

	if (cur_n_bits < 0)
		error_exit("internal error: %d < 0", cur_n_bits);
	cur_n_bytes = (cur_n_bits + 7) / 8;
	dolog(LOG_DEBUG, "get|%s got %d bits from pool", client -> host.c_str(), cur_n_bits);

	int hash_len = client -> mac_hasher -> get_hash_size();
	int out_len = cur_n_bytes + hash_len;
#ifdef CRYPTO_DEBUG
	printf("bytes: %d\n", out_len);
#endif
	unsigned char *ent_buffer_in = reinterpret_cast<unsigned char *>(malloc_locked(out_len));

	memcpy(&ent_buffer_in[hash_len], temp_buffer, cur_n_bytes);
	memset(ent_buffer_in, 0x00, hash_len);

	client -> mac_hasher -> do_hash(&ent_buffer_in[hash_len], cur_n_bytes, ent_buffer_in);

#ifdef CRYPTO_DEBUG
	printf("send: "); hexdump(ent_buffer_in, hash_len);
	printf("data: "); hexdump(&ent_buffer_in[hash_len], 8);
#endif

	unsigned char *ent_buffer = reinterpret_cast<unsigned char *>(malloc(out_len));
	if (!ent_buffer)
		error_exit("error allocating %d bytes of memory", out_len);

	// encrypt data
	client -> stream_cipher -> encrypt(ent_buffer_in, out_len, ent_buffer);
#ifdef CRYPTO_DEBUG
	printf("encr: "); hexdump(ent_buffer, 16);
#endif

	free_locked(temp_buffer, cur_n_bytes + 1);

	// update statistics for accounting
	my_mutex_lock(&client -> stats_lck);
	client -> bits_sent += cur_n_bits;
	my_mutex_unlock(&client -> stats_lck);

	client -> stats_user -> track_sents(cur_n_bits);
	client -> stats_glob -> track_sents(cur_n_bits);

	transmit_size = 4 + 4 + out_len;
	unsigned char *output_buffer = reinterpret_cast<unsigned char *>(malloc(transmit_size));
	if (!output_buffer)
		error_exit("error allocating %d bytes of memory", cur_n_bytes);
	make_msg(output_buffer, 2, cur_n_bits); // 0002

	dolog(LOG_DEBUG, "get|%s transmit size: %d, msg: %s", client -> host.c_str(), transmit_size, output_buffer);

	memcpy(&output_buffer[8], ent_buffer, out_len);

	free(ent_buffer);

	free_locked(ent_buffer_in, cur_n_bytes);

	int rc = 0;
	if (WRITE_TO(client -> socket_fd, output_buffer, transmit_size, client -> config -> communication_timeout) != transmit_size)
	{
		dolog(LOG_INFO, "%s error while sending data to client", client -> host.c_str());

		rc = -1;
	}

	free(output_buffer);

	return rc;
}

int do_client_put(client_t *client, bool *new_bits, bool *is_full)
{
	bool warn_all_full = false;

	*new_bits = false;

	if (client -> ppools -> all_pools_full(double(client -> config -> communication_timeout) * 0.9))
	{
		*is_full = true;

		client -> stats_user -> inc_n_times_full();

		double last_submit_ago = get_ts() - client -> stats_glob -> get_last_put_msg_ts();
		char full_allow_interval_submit = last_submit_ago >= client -> config -> when_pools_full_allow_submit_interval;

		if (!(client -> config -> add_entropy_even_if_all_full || full_allow_interval_submit))
		{
			char dummy_buffer[4];

			if (READ_TO(client -> socket_fd, dummy_buffer, 4, client -> config -> communication_timeout) != 4)	// flush number of bits
				return -1;

			return send_denied_full(client -> socket_fd, client -> stats_glob, client -> config, client -> host);
		}

		if (full_allow_interval_submit)
			dolog(LOG_DEBUG, "put|%s(%s) allow submit when full, after %f seconds", client -> host.c_str(), client -> type.c_str(), last_submit_ago);

		warn_all_full = true;
	}

	unsigned char n_bits[4];
	if (READ_TO(client -> socket_fd, n_bits, 4, client -> config -> communication_timeout) != 4)
	{
		dolog(LOG_INFO, "put|%s(%s) short read while retrieving number of bits to recv", client -> host.c_str(), client -> type.c_str());
		return -1;
	}

	int cur_n_bits = uchar_to_uint(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "put|%s(%s) 0 bits requested", client -> host.c_str(), client -> type.c_str());
		return -1;
	}
	if (cur_n_bits > client -> config -> max_get_put_size)
	{
		dolog(LOG_WARNING, "put|%s(%s) client requested more than %d bits: %d", client -> host.c_str(), client -> type.c_str(), client -> config -> max_get_put_size, cur_n_bits);
		return -1;
	}

	unsigned char msg[4 + 4];
	if (warn_all_full)
		make_msg(msg, 9003, cur_n_bits);
	else
		make_msg(msg, 1, cur_n_bits); // 0001
	if (WRITE_TO(client -> socket_fd, msg, 8, client -> config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "put|%s short write while sending ack", client -> host.c_str());
		return -1;
	}

	int cur_n_bytes = (cur_n_bits + 7) / 8;

	int hash_len = client -> mac_hasher -> get_hash_size();
	int in_len = cur_n_bytes + hash_len;
	unsigned char *buffer_in = reinterpret_cast<unsigned char *>(malloc(in_len));
	if (!buffer_in)
		error_exit("%s error allocating %d bytes of memory", client -> host.c_str(), in_len);

	if (READ_TO(client -> socket_fd, buffer_in, in_len, client -> config -> communication_timeout) != in_len)
	{
		dolog(LOG_INFO, "put|%s short read while retrieving entropy data", client -> host.c_str());

		free(buffer_in);

		return -1;
	}

	unsigned char *buffer_out = reinterpret_cast<unsigned char *>(malloc_locked(in_len));
	if (!buffer_out)
		error_exit("%s error allocating %d bytes of memory", client -> host.c_str(), cur_n_bytes);

	// decrypt data
	client -> stream_cipher -> decrypt(buffer_in, in_len, buffer_out);

	unsigned char *entropy_data = &buffer_out[hash_len];
	int entropy_data_len = cur_n_bytes;
	unsigned char *hash = reinterpret_cast<unsigned char *>(malloc(hash_len));

	client -> mac_hasher -> do_hash(entropy_data, entropy_data_len, hash);

	if (memcmp(hash, buffer_out, hash_len) != 0)
		dolog(LOG_WARNING, "Hash mismatch in retrieved entropy data!");
	else
	{
		int n_bits_added = client -> ppools -> add_bits_to_pools(entropy_data, entropy_data_len, client -> ignore_rngtest_fips140, client -> pfips140, client -> ignore_rngtest_scc, client -> pscc, double(client -> config -> communication_timeout) * 0.9, client -> pc);
		if (n_bits_added == -1)
			dolog(LOG_CRIT, "put|%s error while adding data to pools", client -> host.c_str());
		else
			dolog(LOG_DEBUG, "put|%s %d bits mixed into pools", client -> host.c_str(), n_bits_added);

		my_mutex_lock(&client -> stats_lck);
		client -> bits_recv += n_bits_added;
		my_mutex_unlock(&client -> stats_lck);

		client -> stats_user -> track_recvs(n_bits_added);
		client -> stats_glob -> track_recvs(n_bits_added);

		*new_bits = true;
	}

	free(hash);

	free_locked(buffer_out, cur_n_bytes);

	free(buffer_in);

	return 0;
}

int do_client(client_t *client, bool *no_bits, bool *new_bits, bool *is_full)
{
	char cmd[4];

	double now = get_ts();

	client -> stats_user -> inc_msg_cnt();
	client -> stats_glob -> inc_msg_cnt();

	int rc = READ_TO(client -> socket_fd, cmd, 4, client -> config -> communication_timeout);
	if (rc != 4)
	{
		dolog(LOG_INFO, "client|%s short read while retrieving command (%d)", client -> host.c_str(), rc);
		return -1;
	}

	if (memcmp(cmd, "0001", 4) == 0)		// GET bits
	{
		client -> stats_user -> register_msg(false);
		client -> stats_glob -> register_msg(false);
		return do_client_get(client, no_bits);
	}
	else if (memcmp(cmd, "0002", 4) == 0)	// PUT bits
	{
		client -> stats_user -> register_msg(true);
		client -> stats_glob -> register_msg(true);
		return do_client_put(client, new_bits, is_full);
	}

	client -> stats_user -> register_msg(false);
	client -> stats_glob -> register_msg(false);
	dolog(LOG_INFO, "client|%s command '%s' unknown", client -> host.c_str(), cmd);

	return -1;
}

int notify_server_full(int socket_fd, statistics *stats, config_t *config)
{
	unsigned char buffer[8];

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
