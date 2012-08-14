#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <openssl/blowfish.h>
#include <vector>
#include <string>

#include "error.h"
#include "log.h"
#include "math.h"
#include "ivec.h"
#include "pool.h"
#include "fips140.h"
#include "config.h"
#include "scc.h"
#include "pools.h"
#include "handle_client.h"
#include "utils.h"
#include "signals.h"
#include "auth.h"
#include "protocol.h"

extern const char *pid_file;

int send_denied_empty(int fd, statistics_t *stats, config_t *config)
{
	int seconds = config -> default_sleep_when_pools_empty; // & default_max_sleep_when_pools_empty
	char buffer[4+4+1];

	stats -> n_times_empty++;

	make_msg(buffer, 9000, seconds);

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_quota(int fd, statistics_t *stats, config_t *config)
{
	char buffer[4+4+1];

	stats -> n_times_quota++;

	make_msg(buffer, 9002, config -> reset_counters_interval);

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_full(client_t *client, pools *ppools, statistics_t *stats, config_t *config)
{
	char buffer[4+4+1];
	int seconds = config -> default_sleep_time_when_pools_full;

	stats -> n_times_full++;

	make_msg(buffer, 9001, seconds);

	dolog(LOG_INFO, "denied|%s all pools full, sleep of %d seconds", client -> host, seconds);

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_accepted_while_full(client_t *client, config_t *config)
{
	char buffer[4+4+1];

	make_msg(buffer, 9003, config -> default_sleep_time_when_pools_full);

	dolog(LOG_INFO, "meta|%s all pools full", client -> host);

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int send_got_data(int fd, pools *ppools, config_t *config)
{
	char buffer[4+4+1];

	// data is an estimate; it can be different anyway as other clients may come first
	make_msg(buffer, 9, min(9999, ppools -> get_bit_sum())); // 0009

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_need_data(int fd, config_t *config)
{
	char buffer[4+4+1];

	make_msg(buffer, 10, 0); // 0010 0000

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int do_client_get(pools *ppools, client_t *client, statistics_t *stats, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc, BF_KEY *key, bool *no_bits)
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

	cur_n_bits = min(cur_n_bits, client -> max_bits_per_interval - client -> bits_sent);
	dolog(LOG_DEBUG, "get|%s is allowed to now receive %d bits", client -> host, cur_n_bits);
	if (cur_n_bits == 0)
		return send_denied_quota(client -> socket_fd, stats, config);
	if (cur_n_bits < 0)
		error_exit("cur_n_bits < 0");

	cur_n_bytes = (cur_n_bits + 7) / 8;

	dolog(LOG_DEBUG, "get|%s memory allocated, retrieving bits", client -> host);

	unsigned char *ent_buffer_in = NULL;
	cur_n_bits = ppools -> get_bits_from_pools(cur_n_bits, &ent_buffer_in, client -> allow_prng, client -> ignore_rngtest_fips140, eb_output_fips140, client -> ignore_rngtest_scc, eb_output_scc);
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

	unsigned char *ent_buffer = (unsigned char *)malloc(cur_n_bytes);
	if (!ent_buffer)
		error_exit("error allocating %d bytes of memory", cur_n_bytes);

	// encrypt data. keep original data; will be used as ivec for next round
	int num = 0;
	BF_cfb64_encrypt(ent_buffer_in, ent_buffer, cur_n_bytes, key, client -> ivec, &num, BF_ENCRYPT);
	memcpy(client -> ivec, ent_buffer_in, min(8, cur_n_bytes));

	// update statistics for accounting
	client -> bits_sent += cur_n_bits;
	stats -> bps_cur += cur_n_bits;
	stats -> total_sent += cur_n_bits;
	stats -> total_sent_requests++;

	transmit_size = 4 + 4 + cur_n_bytes;
	unsigned char *output_buffer = (unsigned char *)malloc(transmit_size);
	if (!output_buffer)
		error_exit("error allocating %d bytes of memory", cur_n_bytes);
	make_msg((char *)output_buffer, 2, cur_n_bits); // 0002

	dolog(LOG_DEBUG, "get|%s transmit size: %d, msg: %s", client -> host, transmit_size, output_buffer);

	memcpy(&output_buffer[8], ent_buffer, cur_n_bytes);

	free(ent_buffer);

	memset(ent_buffer_in, 0x00, cur_n_bytes);
	unlock_mem(ent_buffer_in, cur_n_bytes);
	free(ent_buffer_in);

	int rc = 0;
	if (WRITE_TO(client -> socket_fd, (char *)output_buffer, transmit_size, config -> communication_timeout) != transmit_size)
	{
		dolog(LOG_INFO, "%s error while sending to client", client -> host);

		rc = -1;
	}

	free(output_buffer);

	return rc;
}

int do_client_put(pools *ppools, client_t *client, statistics_t *stats, config_t *config, BF_KEY *key, bool *new_bits, bool *is_full)
{
	char msg[4+4+1];
	int cur_n_bits, cur_n_bytes;
	int n_bits_added;
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

	unsigned char *buffer_in = (unsigned char *)malloc(cur_n_bytes);
	if (!buffer_in)
		error_exit("%s error allocating %d bytes of memory", client -> host, cur_n_bytes);
	unsigned char *buffer_out = (unsigned char *)malloc(cur_n_bytes);
	if (!buffer_out)
		error_exit("%s error allocating %d bytes of memory", client -> host, cur_n_bytes);
	lock_mem(buffer_out, cur_n_bytes);

	if (READ_TO(client -> socket_fd, (char *)buffer_in, cur_n_bytes, config -> communication_timeout) != cur_n_bytes)
	{
		dolog(LOG_INFO, "put|%s short read while retrieving entropy data", client -> host);

		free(buffer_out);

		memset(buffer_in, 0x00, cur_n_bytes);
		free(buffer_in);

		return -1;
	}

	// decrypt data. decrypted data will be used as ivec for next round
	int num = 0;
	BF_cfb64_encrypt(buffer_in, buffer_out, cur_n_bytes, key, client -> ivec, &num, BF_DECRYPT);
	memcpy(client -> ivec, buffer_out, min(cur_n_bytes, 8));

	client -> last_put_message = now;

	n_bits_added = ppools -> add_bits_to_pools(buffer_out, cur_n_bytes, client -> ignore_rngtest_fips140, client -> pfips140, client -> ignore_rngtest_scc, client -> pscc);
	if (n_bits_added == -1)
		dolog(LOG_CRIT, "put|%s error while adding data to pools", client -> host);
	else
		dolog(LOG_DEBUG, "put|%s %d bits mixed into pools", client -> host, n_bits_added);

	client -> bits_recv += n_bits_added;
	stats -> total_recv += n_bits_added;
	stats -> total_recv_requests++;
	*new_bits = true;

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
	char *buffer;
	int n_bytes;
	char string_size[4 + 1];

	if (READ_TO(client -> socket_fd, string_size, 4, config -> communication_timeout) != 4)	// flush number of bits
		return -1;

	string_size[4] = 0x00;

	n_bytes = atoi(string_size);
	if (n_bytes <= 0)
	{
		dolog(LOG_WARNING, "%s sends 0003 msg with 0 bytes of contents", client -> host);
		return -1;
	}

	buffer = (char *)malloc(n_bytes + 1);
	if (!buffer)
		error_exit("%s out of memory while allocating %d bytes", client -> host, n_bytes + 1);

	if (READ_TO(client -> socket_fd, buffer, n_bytes, config -> communication_timeout) != n_bytes)
	{
		free(buffer);
		dolog(LOG_INFO, "type|%s short read for 0003", client -> host);
		return -1;
	}

	buffer[n_bytes] = 0x00;

	strncpy(client -> type, buffer, sizeof(client -> type));
	(client -> type)[sizeof(client -> type) - 1] = 0x00;
	dolog(LOG_INFO, "type|%s is \"%s\"", client -> host, client -> type);

	free(buffer);

	return 0;
}

int do_client_send_ping_request(client_t *client, config_t *config)
{
	char buffer[8 + 1];

	make_msg(buffer, 4, client -> ping_nr); // 0004

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "ping|Short write while sending ping request to %s", client -> host);
		return -1;
	}

	dolog(LOG_DEBUG, "ping|Ping request %d sent to %s", client -> ping_nr, client -> host);

	client -> ping_nr++;

	return 0;
}

int do_client_ping_reply(client_t *client, config_t *config)
{
	char buffer[4 + 1];

	if (READ_TO(client -> socket_fd, buffer, 4, config -> communication_timeout) != 4)	// flush number of bits
		return -1;

	buffer[4] = 0x00;

	dolog(LOG_DEBUG, "ping|Got successfull ping reply from %s (%s): %s", client -> host, client -> type, buffer);

	return 0;
}

int do_client_kernelpoolfilled_reply(client_t *client, config_t *config)
{
	char *buffer;
	int n_bytes;
	char string_size[4 + 1];

	if (READ_TO(client -> socket_fd, string_size, 4, config -> communication_timeout) != 4)	// flush number of bits
		return -1;

	string_size[4] = 0x00;

	n_bytes = atoi(string_size);
	if (n_bytes <= 0)
	{
		dolog(LOG_WARNING, "%s sends 0008 msg with 0 bytes of contents", client -> host);
		return -1;
	}

	buffer = (char *)malloc(n_bytes + 1);
	if (!buffer)
		error_exit("%s out of memory while allocating %d bytes", client -> host, n_bytes + 1);

	if (READ_TO(client -> socket_fd, buffer, n_bytes, config -> communication_timeout) != n_bytes)
	{
		free(buffer);
		dolog(LOG_INFO, "kernfill|%s short read for 0008", client -> host);
		return -1;
	}

	buffer[n_bytes] = 0x00;

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

int do_client(pools *ppools, client_t *client, statistics_t *stats, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc, BF_KEY *key, bool *no_bits, bool *new_bits, bool *is_full)
{
	char cmd[4 + 1];
	cmd[4] = 0x00;

	int rc = READ_TO(client -> socket_fd, cmd, 4, config -> communication_timeout);
	if (rc != 4)
	{
		dolog(LOG_INFO, "client|%s short read while retrieving command (%d)", client -> host, rc);
		return -1;
	}

	if (strcmp(cmd, "0001") == 0)		// GET bits
	{
		// this flag could also be named 'is_interested_to_know_if_there_is_data'
		client -> data_avail_signaled = false;

		return do_client_get(ppools, client, stats, config, eb_output_fips140, eb_output_scc, key, no_bits);
	}
	else if (strcmp(cmd, "0002") == 0)	// PUT bits
	{
		return do_client_put(ppools, client, stats, config, key, new_bits, is_full);
	}
	else if (strcmp(cmd, "0003") == 0)	// server type
	{
		client -> is_server = 1;
		return do_client_server_type(client, config);
	}
	else if (strcmp(cmd, "0005") == 0)	// ping reply (to 0004)
	{
		return do_client_ping_reply(client, config);
	}
	else if (strcmp(cmd, "0006") == 0)	// client type
	{
		client -> is_server = 0;
		return do_client_server_type(client, config);
	}
	else if (strcmp(cmd, "0008") == 0)	// # bits in kernel reply (to 0007)
	{
		return do_client_kernelpoolfilled_reply(client, config);
	}
	else
	{
		dolog(LOG_INFO, "client|%s command '%s' unknown", client -> host, cmd);
		return -1;
	}

	dolog(LOG_DEBUG, "client|finished %s command for %s, pool bits: %d, client sent/recv: %d/%d", cmd, client -> host, ppools -> get_bit_sum(), client -> bits_sent, client -> bits_recv);

	return 0;
}

void forget_client(client_t *clients, int *n_clients, int nr)
{
	int n_to_move;

	close(clients[nr].socket_fd);
	delete clients[nr].pfips140;
	delete clients[nr].pscc;

	n_to_move = (*n_clients - nr) - 1;
	if (n_to_move > 0)
		memmove(&clients[nr], &clients[nr + 1], sizeof(client_t) * n_to_move);
	(*n_clients)--;
}

void notify_servers_full(client_t *clients, int *n_clients, statistics_t *stats, config_t *config)
{
	char buffer[8 + 1];

	make_msg(buffer, 9004, 0); // 9004

	for(int loop=*n_clients - 1; loop>=0; loop--)
	{
		if (!clients[loop].is_server)
			continue;

		if (WRITE_TO(clients[loop].socket_fd, buffer, 8, config -> communication_timeout) != 8)
		{
			dolog(LOG_INFO, "kernfill|Short write while sending full notification request to %s", clients[loop].host);

			stats -> disconnects++;

			forget_client(clients, n_clients, loop);
		}
	}
}

void notify_clients_data_available(client_t *clients, int *n_clients, statistics_t *stats, pools *ppools, config_t *config)
{
	for(int loop=*n_clients - 1; loop>=0; loop--)
	{
		if (clients[loop].is_server)
			continue;

		if (clients[loop].data_avail_signaled)
			continue;

		clients[loop].data_avail_signaled = true;
		if (send_got_data(clients[loop].socket_fd, ppools, config) == -1)
		{
			dolog(LOG_INFO, "main|connection closed, removing client %s from list", clients[loop].host);
			dolog(LOG_DEBUG, "main|%s: %s, scc: %s", clients[loop].host, clients[loop].pfips140 -> stats(), clients[loop].pscc -> stats());

			stats -> disconnects++;

			forget_client(clients, n_clients, loop);
		}
	}
}

void notify_servers_data_needed(client_t *clients, int *n_clients, statistics_t *stats, config_t *config)
{
	for(int loop=*n_clients - 1; loop>=0; loop--)
	{
		if (!clients[loop].is_server)
			continue;

		if (send_need_data(clients[loop].socket_fd, config) == -1)
		{
			dolog(LOG_INFO, "main|connection closed, removing client %s from list", clients[loop].host);
			dolog(LOG_DEBUG, "main|%s: %s, scc: %s", clients[loop].host, clients[loop].pfips140 -> stats(), clients[loop].pscc -> stats());

			stats -> disconnects++;

			forget_client(clients, n_clients, loop);
		}
	}
}

void process_timed_out_cs(config_t *config, client_t *clients, int *n_clients, statistics_t *stats)
{
	if (config -> communication_session_timeout > 0)
	{
		double now = get_ts();

		for(int loop=*n_clients - 1; loop>=0; loop--)
		{
			double time_left_in_session = (clients[loop].last_message + (double)config -> communication_session_timeout) - now;

			if (time_left_in_session <= 0.0)
			{
				dolog(LOG_INFO, "main|connection timeout, removing client %s from list", clients[loop].host);
				dolog(LOG_DEBUG, "%s: %s", clients[loop].host, clients[loop].pfips140 -> stats());

				stats -> timeouts++;

				forget_client(clients, n_clients, loop);
			}
		}
	}
}

int lookup_client_settings(struct sockaddr_in *client_addr, client_t *client, config_t *config)
{
	// FIXME
	client -> max_bits_per_interval = config -> default_max_bits_per_interval;
	client -> ignore_rngtest_fips140 = config -> ignore_rngtest_fips140;
	client -> ignore_rngtest_scc = config -> ignore_rngtest_scc;
	client -> allow_prng = config -> allow_prng;

	return 0;
}

void register_new_client(int listen_socket_fd, client_t **clients, int *n_clients, config_t *config)
{
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int new_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);

	if (new_socket_fd != -1)
	{
		dolog(LOG_INFO, "main|new client: %s:%d (fd: %d)", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, new_socket_fd);

		if (config -> disable_nagle)
			disable_nagle(new_socket_fd);

		if (config -> enable_keepalive)
			enable_tcp_keepalive(new_socket_fd);

		bool ok = auth_eb(new_socket_fd, config -> auth_password, config -> communication_timeout) == 0;

		if (!ok)
		{
			close(new_socket_fd);
			dolog(LOG_WARNING, "main|client: %s:%d (fd: %d) authentication failed", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, new_socket_fd);
		}
		else
		{
			(*n_clients)++;

			*clients = (client_t *)realloc(*clients, *n_clients * sizeof(client_t));
			if (!*clients)
				error_exit("memory allocation error");

			int nr = *n_clients - 1;
			client_t *p = &(*clients)[nr];

			memset(p, 0x00, sizeof(client_t));
			p -> socket_fd = new_socket_fd;
			int dummy = sizeof(p -> host);
			snprintf(p -> host, dummy, "%s:%d", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
			p -> pfips140 = new fips140();
			p -> pscc = new scc();
			double now = get_ts();
			p -> last_message = now;
			p -> connected_since = now;
			p -> last_put_message = now;
			p -> pfips140 -> set_user(p -> host);
			p -> pscc     -> set_user(p -> host);
			p -> pscc -> set_threshold(config -> scc_threshold);
			memcpy(p -> ivec, config -> auth_password, min(strlen(config -> auth_password), 8));

			if (lookup_client_settings(&client_addr, p, config) == -1)
			{
				dolog(LOG_INFO, "main|client %s not found, terminating connection", p -> host);

				delete p -> pfips140;
				delete p -> pscc;

				(*n_clients)--;

				close(new_socket_fd);
			}
		}
	}
}

void request_kp_filled(client_t *clients, int *n_clients, config_t *config, statistics_t *stats)
{
	for(int loop=*n_clients - 1; loop>=0; loop--)
	{
		if (!clients[loop].is_server && do_client_kernelpoolfilled_request(&clients[loop], config) == -1)
		{
			stats -> disconnects++;

			forget_client(clients, n_clients, loop);
		}
	}
}

void send_pings(client_t *clients, int *n_clients, config_t *config, statistics_t *stats)
{
	for(int loop=*n_clients - 1; loop>=0; loop--)
	{
		if (clients[loop].is_server)
			continue;

		if (do_client_send_ping_request(&clients[loop], config) == -1)
		{
			stats -> disconnects++;

			forget_client(clients, n_clients, loop);
		}
	}
}

void emit_statistics_file(config_t *config, statistics_t *stats, int n_clients, pools *ppools, scc *eb_output_scc)
{
	if (config -> stats_file)
	{
		FILE *fh = fopen(config -> stats_file, "a+");
		if (!fh)
			error_exit("cannot access file %s", config -> stats_file);

		struct rusage usage;
		if (getrusage(RUSAGE_SELF, &usage) == -1)
			error_exit("getrusage() failed");

		double proc_usage = (double)usage.ru_utime.tv_sec + (double)usage.ru_utime.tv_usec / 1000000.0 +
			(double)usage.ru_stime.tv_sec + (double)usage.ru_stime.tv_usec / 1000000.0;

		double now = get_ts();
		int total_n_bits = ppools -> get_bit_sum();
		fprintf(fh, "%f %lld %lld %d %d %d %d %f %s\n", now, stats -> total_recv, stats -> total_sent,
				stats -> total_recv_requests, stats -> total_sent_requests,
				n_clients, total_n_bits, proc_usage, eb_output_scc -> stats());

		fclose(fh);
	}
}

void emit_statistics_log(config_t *config, statistics_t *stats, pools *ppools, client_t *clients, int n_clients, bool force_stats, fips140 *f1, scc *sc, double start_ts)
{
	int total_n_bits = ppools -> get_bit_sum();
	double now = get_ts();
	double runtime = now - start_ts;

	if (!force_stats)
	{
		for(int loop=0; loop<n_clients; loop++)
			clients[loop].bits_recv = clients[loop].bits_sent = 0;
	}

	stats -> bps = stats -> bps_cur / config -> reset_counters_interval;
	stats -> bps_cur = 0;

	dolog(LOG_DEBUG, "stats|client bps: %d (in last %ds interval), disconnects: %d", stats -> bps, config -> reset_counters_interval, stats -> disconnects);
	dolog(LOG_DEBUG, "stats|total recv: %ld (%fbps), total sent: %ld (%fbps), run time: %f", stats -> total_recv, double(stats -> total_recv) / runtime, stats -> total_sent, double(stats -> total_sent) / runtime, runtime);
	dolog(LOG_DEBUG, "stats|recv requests: %d, sent: %d, clients/servers: %d, bits: %d", stats -> total_recv_requests, stats -> total_sent_requests, n_clients, total_n_bits);
	dolog(LOG_DEBUG, "stats|%s, scc: %s", f1 -> stats(), sc -> stats());
}

void main_loop(pools *ppools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc)
{
	client_t *clients = NULL;
	int n_clients = 0;
	double last_counters_reset = get_ts();
	double last_statistics_emit = get_ts();
	double last_ping = get_ts() - double(config -> ping_interval) + 10.0;
	double last_kp_filled = get_ts();
	event_state_t event_state;
	int listen_socket_fd = start_listen(config -> listen_adapter, config -> listen_port, config -> listen_queue_size);
	statistics_t	stats;
	double start_ts = get_ts();

	memset(&event_state, 0x00, sizeof(event_state));
	memset(&stats, 0x00, sizeof(stats));

	dolog(LOG_INFO, "main|main-loop started");

	BF_KEY key;
	BF_set_key(&key, strlen(config -> auth_password), (unsigned char *)config -> auth_password);

	bool no_bits = false, new_bits = false, prev_is_full = false;
	for(;;)
	{
		int loop, rc;
		fd_set rfds;
		double now = get_ts();
		struct timespec tv;
		int max_fd = 0;
		double time_left = 300.0, dummy1_time;
		char force_stats = 0;
		sigset_t sig_set;

		if (sigemptyset(&sig_set) == -1)
			error_exit("sigemptyset");

		FD_ZERO(&rfds);

		dummy1_time = max(0, (last_statistics_emit + config -> statistics_interval) - now);
		time_left = min(time_left, dummy1_time);
		dummy1_time = max(0, (last_counters_reset + config -> reset_counters_interval) - now);
		time_left = min(time_left, dummy1_time);
		dummy1_time = max(0, (last_ping + config -> ping_interval) - now);
		time_left = min(time_left, dummy1_time);
		dummy1_time = max(0, (last_kp_filled  + config -> kernelpool_filled_interval) - now);
		time_left = min(time_left, dummy1_time);

		for(loop=0; loop<n_clients; loop++)
		{
			FD_SET(clients[loop].socket_fd, &rfds);
			max_fd = max(max_fd, clients[loop].socket_fd);

			if (config -> communication_session_timeout > 0)
				time_left = min(time_left, max(0, (clients[loop].last_message + (double)config -> communication_session_timeout) - now));
		}

		FD_SET(listen_socket_fd, &rfds);
		max_fd = max(max_fd, listen_socket_fd);

		tv.tv_sec = time_left;
		tv.tv_nsec = (time_left - (double)tv.tv_sec) * 1000000000.0;

		rc = pselect(max_fd + 1, &rfds, NULL, NULL, &tv, &sig_set);

		if (is_SIGHUP())
		{
			dolog(LOG_DEBUG, "Got SIGHUP");
			reset_SIGHUP();
			force_stats = 1;
		}

		if (is_SIGEXIT())
		{
			dolog(LOG_INFO, "Program stopping due to either SIGTERM, SIGQUIT or SIGINT");
			unlink(pid_file);
			break;
		}

		if (rc == -1)
		{
			if (errno == EBADF || errno == ENOMEM || errno == EINVAL)
				error_exit("pselect() failed");

			if (errno == EINTR)
				continue;
		}

		now = get_ts();

		if (config -> allow_event_entropy_addition)
		{
			int event_bits = ppools -> add_event(now, (unsigned char *)&rfds, sizeof(rfds));
			dolog(LOG_DEBUG, "main|added %d bits of event-entropy to pool", event_bits);
		}

		if (((last_counters_reset + (double)config -> reset_counters_interval) - now) <= 0 || force_stats)
		{
			emit_statistics_log(config, &stats, ppools, clients, n_clients, force_stats, eb_output_fips140, eb_output_scc, start_ts);

			last_counters_reset = now;
		}

		if ((config -> statistics_interval != 0 && ((last_statistics_emit + (double)config -> statistics_interval) - now) <= 0) || force_stats)
		{
			emit_statistics_file(config, &stats, n_clients, ppools, eb_output_scc);

			last_statistics_emit = now;
		}

		if (config -> ping_interval != 0 && ((last_ping + (double)config -> ping_interval) - now) <= 0)
		{
			send_pings(clients, &n_clients, config, &stats);

			last_ping = now;
		}

		if (config -> kernelpool_filled_interval !=0 && ((last_kp_filled + (double)config -> kernelpool_filled_interval) - now) <= 0)
		{
			request_kp_filled(clients, &n_clients, config, &stats);

			last_kp_filled = now;
		}

		if (force_stats)
		{
			for(loop=0; loop<n_clients; loop++)
				dolog(LOG_DEBUG, "stats|%s (%s): %s, scc: %s | sent: %d, recv: %d | last msg: %ld seconds ago, %lds connected",
						clients[loop].host, clients[loop].type, clients[loop].pfips140 -> stats(),
						clients[loop].pscc -> stats(),
						clients[loop].bits_sent, clients[loop].bits_recv, (long int)(now - clients[loop].last_message), (long int)(now - clients[loop].connected_since));
		}

		new_bits = false;
		if (rc > 0)
		{
			bool is_full = false;

			for(loop=n_clients - 1; loop>=0; loop--)
			{
				if (FD_ISSET(clients[loop].socket_fd, &rfds))
				{
					clients[loop].last_message = now;

					bool cur_no_bits = false, cur_new_bits = false;
					if (do_client(ppools, &clients[loop], &stats, config, eb_output_fips140, eb_output_scc, &key, &cur_no_bits, &cur_new_bits, &is_full) == -1)
					{
						dolog(LOG_INFO, "main|connection closed, removing client %s from list", clients[loop].host);
						dolog(LOG_DEBUG, "main|%s: %s, scc: %s", clients[loop].host, clients[loop].pfips140 -> stats(), clients[loop].pscc -> stats());

						stats.disconnects++;

						forget_client(clients, &n_clients, loop);
					}

					if (cur_no_bits)
					{
						no_bits = true;
						new_bits = false;
					}
					else if (cur_new_bits)
					{
						new_bits = true;
					}
				}

				// printf("NBWB %d %d\n", no_bits, new_bits);
			}

			if (no_bits)
			{
				dolog(LOG_DEBUG, "Bits needed");

				// might need to remember if we already sent this message in case
				// too many of these messages are send
				notify_servers_data_needed(clients, &n_clients, &stats, config);

				if (new_bits)
				{
					dolog(LOG_DEBUG, "New bits: alerting clients");

					no_bits = new_bits = false;

					notify_clients_data_available(clients, &n_clients, &stats, ppools, config);
				}
			}

			if (is_full == true && prev_is_full == false)
			{
				notify_servers_full(clients, &n_clients, &stats, config);
			}
			prev_is_full = is_full;

			if (FD_ISSET(listen_socket_fd, &rfds))
			{
				register_new_client(listen_socket_fd, &clients, &n_clients, config);
			}
		}

		/* session time-outs */
		process_timed_out_cs(config, clients, &n_clients, &stats);
	}

	dolog(LOG_WARNING, "main|end of main loop");
}
