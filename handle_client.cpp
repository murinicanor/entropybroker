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

#include "error.h"
#include "log.h"
#include "pool.h"
#include "fips140.h"
#include "config.h"
#include "scc.h"
#include "handle_client.h"
#include "handle_pool.h"
#include "utils.h"
#include "signals.h"
#include "auth.h"

extern const char *pid_file;

int send_denied_empty(int fd, statistics_t *stats, config_t *config)
{
	int seconds = config -> default_sleep_when_pools_empty; // & default_max_sleep_when_pools_empty
	char buffer[4+4+1];

	stats -> n_times_empty++;

	// FIXME seconds = ... depending on stats

	snprintf(buffer, sizeof(buffer), "9000%04d", seconds);

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_quota(int fd, statistics_t *stats, config_t *config)
{
	char buffer[4+4+1];

	stats -> n_times_quota++;

	snprintf(buffer, sizeof(buffer), "9002%04d", config -> reset_counters_interval);

	return WRITE_TO(fd, buffer, 8, config -> communication_timeout) == 8 ? 0 : -1;
}

int send_denied_full(client_t *client, pool **pools, int n_pools, statistics_t *stats, config_t *config)
{
	char buffer[4+4+1];
	int seconds = config -> default_sleep_time_when_pools_full;

	stats -> n_times_full++;

	if (stats -> bps != 0)
	{
		// determine how many seconds it'll take before the current pool is empty
		int n_bits_in_pool = get_bit_sum(pools, n_pools);
		seconds = min(config -> default_max_sleep_when_pool_full, max(1, (n_bits_in_pool * 0.75) / max(1, stats -> bps)));
	}

	sprintf(buffer, "9001%04d", seconds);
	dolog(LOG_INFO, "denied|%s all pools full, sleep of %d seconds", client -> host, seconds);

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
		return -1;

	return 0;
}

int do_client_get(pool **pools, int n_pools, client_t *client, statistics_t *stats, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc)
{
	unsigned char *buffer, *ent_buffer;
	int cur_n_bits, cur_n_bytes;
	int transmit_size;
	char n_bits[4 + 1];
	n_bits[4] = 0x00;

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
		return send_denied_quota(client -> socket_fd, stats, config); // FIXME: send_denied_quota
	if (cur_n_bits < 0)
		error_exit("cur_n_bits < 0");

	cur_n_bytes = (cur_n_bits + 7) / 8;

	dolog(LOG_DEBUG, "get|%s memory allocated, retrieving bits", client -> host);

	cur_n_bits = get_bits_from_pools(cur_n_bits, pools, n_pools, &ent_buffer, client -> allow_prng, client -> ignore_rngtest_fips140, eb_output_fips140, client -> ignore_rngtest_scc, eb_output_scc);
	if (cur_n_bits == 0)
	{
		dolog(LOG_WARNING, "get|%s no bits in pools", client -> host);
		free(ent_buffer);
		return send_denied_empty(client -> socket_fd, stats, config);
	}
	if (cur_n_bits < 0)
		error_exit("internal error: %d < 0", cur_n_bits);
	cur_n_bytes = (cur_n_bits + 7) / 8;
	dolog(LOG_DEBUG, "get|%s got %d bits from pool", client -> host, cur_n_bits);

	// update statistics for accounting
	client -> bits_sent += cur_n_bits;
	stats -> bps_cur += cur_n_bits;
	stats -> total_sent += cur_n_bits;
	stats -> total_sent_requests++;

	transmit_size = 4 + 4 + cur_n_bytes;
	buffer = (unsigned char *)malloc(transmit_size);
	if (!buffer)
		error_exit("error allocating %d bytes of memory", cur_n_bytes);
	sprintf((char *)buffer, "0002%04d", cur_n_bits);

	dolog(LOG_DEBUG, "get|%s transmit size: %d, msg: %s", client -> host, transmit_size, buffer);

	memcpy(&buffer[8], ent_buffer, cur_n_bytes);
	free(ent_buffer);

	if (WRITE_TO(client -> socket_fd, (char *)buffer, transmit_size, config -> communication_timeout) != transmit_size)
	{
		dolog(LOG_INFO, "%s error while sending to client", client -> host);
		free(buffer);
		return -1;
	}

	free(buffer);

	return 0;
}

int do_client_put(pool **pools, int n_pools, client_t *client, statistics_t *stats, config_t *config)
{
	unsigned char *buffer = NULL;
	char msg[4+4+1];
	int cur_n_bits, cur_n_bytes;
	int n_bits_added;
	char n_bits[4 + 1];
	double now = get_ts();

	if (all_pools_full(pools, n_pools))
	{
		double last_submit_ago = now - client -> last_put_message;
		char full_allow_interval_submit = last_submit_ago >= config -> when_pools_full_allow_submit_interval;

		if (!(config -> add_entropy_even_if_all_full || full_allow_interval_submit))
		{
			char dummy_buffer[4];

			if (READ_TO(client -> socket_fd, dummy_buffer, 4, config -> communication_timeout) != 4)	// flush number of bits
				return -1;

			return send_denied_full(client, pools, n_pools, stats, config);
		}

		if (full_allow_interval_submit)
			dolog(LOG_DEBUG, "put|%s(%s) allow submit when full, after %f seconds", client -> host, client -> type, last_submit_ago);
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

	sprintf(msg, "0001%04d", cur_n_bits);
	if (WRITE_TO(client -> socket_fd, msg, 8, config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "put|%s short write while sending ack", client -> host);
		free(buffer);
		return -1;
	}

	cur_n_bytes = (cur_n_bits + 7) / 8;

	buffer = (unsigned char *)malloc(cur_n_bytes);
	if (!buffer)
		error_exit("%s error allocating %d bytes of memory", client -> host, cur_n_bytes);

	if (READ_TO(client -> socket_fd, (char *)buffer, cur_n_bytes, config -> communication_timeout) != cur_n_bytes)
	{
		dolog(LOG_INFO, "put|%s short read while retrieving entropy data", client -> host);
		free(buffer);
		return -1;
	}

	client -> last_put_message = now;

	n_bits_added = add_bits_to_pools(pools, n_pools, buffer, cur_n_bytes, client -> ignore_rngtest_fips140, client -> pfips140, client -> ignore_rngtest_scc, client -> pscc);
	if (n_bits_added == -1)
		dolog(LOG_CRIT, "put|%s error while adding data to pools", client -> host);
	else
		dolog(LOG_DEBUG, "put|%s %d bits mixed into pools", client -> host, n_bits_added);

	client -> bits_recv += n_bits_added;
	stats -> total_recv += n_bits_added;
	stats -> total_recv_requests++;

	free(buffer);

	return 0;
}

int do_client_server_type(pool **pools, int n_pools, client_t *client, config_t *config)
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

	snprintf(buffer, sizeof(buffer), "0004%04d", client -> ping_nr);

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

	snprintf(buffer, sizeof(buffer), "00070000");

	if (WRITE_TO(client -> socket_fd, buffer, 8, config -> communication_timeout) != 8)
	{
		dolog(LOG_INFO, "kernfill|Short write while sending ping request to %s", client -> host);
		return -1;
	}

	dolog(LOG_DEBUG, "kernfill|Client kernel pool filled request sent to %s", client -> host);

	client -> ping_nr++;

	return 0;
}

int do_client(pool **pools, int n_pools, client_t *client, statistics_t *stats, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc)
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
		return do_client_get(pools, n_pools, client, stats, config, eb_output_fips140, eb_output_scc);
	}
	else if (strcmp(cmd, "0002") == 0)	// PUT bits
	{
		return do_client_put(pools, n_pools, client, stats, config);
	}
	else if (strcmp(cmd, "0003") == 0)	// server type
	{
		client -> is_server = 1;
		return do_client_server_type(pools, n_pools, client, config);
	}
	else if (strcmp(cmd, "0005") == 0)	// ping reply (to 0004)
	{
		return do_client_ping_reply(client, config);
	}
	else if (strcmp(cmd, "0006") == 0)	// client type
	{
		client -> is_server = 0;
		return do_client_server_type(pools, n_pools, client, config);
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

	dolog(LOG_DEBUG, "client|finished %s command for %s, pool bits: %d, client sent/recv: %d/%d", cmd, client -> host, get_bit_sum(pools, n_pools), client -> bits_sent, client -> bits_recv);

	return 0;
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

void main_loop(pool **pools, int n_pools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc)
{
	client_t *clients = NULL;
	int n_clients = 0;
	double last_counters_reset = get_ts();
	double last_statistics_emit = get_ts();
	double last_ping = 0.0;
	double last_kp_filled = get_ts();
	event_state_t event_state;
	int listen_socket_fd = start_listen(config -> listen_adapter, config -> listen_port, config -> listen_queue_size);
	statistics_t	stats;
	double start_ts = get_ts();

	memset(&event_state, 0x00, sizeof(event_state));
	memset(&stats, 0x00, sizeof(stats));

	dolog(LOG_INFO, "main|main-loop started");

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
fprintf(stderr, "%f %f", dummy1_time, time_left);
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
		if (rc == -1)
		{
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

			if (errno == EBADF || errno == ENOMEM || errno == EINVAL)
				error_exit("pselect() failed");
		}
		now = get_ts();

		if (config -> allow_event_entropy_addition)
		{
			int event_bits = add_event(pools, n_pools, now, (unsigned char *)&rfds, sizeof(rfds));
			dolog(LOG_DEBUG, "main|added %d bits of event-entropy to pool", event_bits);
		}

		if (((last_counters_reset + (double)config -> reset_counters_interval) - now) <= 0 || force_stats)
		{
			int total_n_bits = get_bit_sum(pools, n_pools);
			double runtime = now - start_ts;

			if (!force_stats)
			{
				for(loop=0; loop<n_clients; loop++)
				{
					clients[loop].bits_recv = clients[loop].bits_sent = 0;
				}
			}

			stats.bps = stats.bps_cur / config -> reset_counters_interval;
			stats.bps_cur = 0;

			dolog(LOG_DEBUG, "stats|client bps: %d (in last %ds interval), disconnects: %d", stats.bps, config -> reset_counters_interval, stats.disconnects);
			dolog(LOG_DEBUG, "stats|total recv: %ld (%fbps), total sent: %ld (%fbps), run time: %f", stats.total_recv, (double)stats.total_recv/runtime, stats.total_sent, (double)stats.total_sent/runtime, runtime);
			dolog(LOG_DEBUG, "stats|recv requests: %d, sent: %d, clients/servers: %d, bits: %d", stats.total_recv_requests, stats.total_sent_requests, n_clients, total_n_bits);
			dolog(LOG_DEBUG, "stats|%s, scc: %s", eb_output_fips140 -> stats(), eb_output_scc -> stats());

			last_counters_reset = now;
		}

		if ((config -> statistics_interval != 0 && ((last_statistics_emit + (double)config -> statistics_interval) - now) <= 0) || force_stats)
		{
			if (config -> stats_file)
			{
				double proc_usage;
				struct rusage usage;
				int total_n_bits = get_bit_sum(pools, n_pools);
				FILE *fh = fopen(config -> stats_file, "a+");
				if (!fh)
					error_exit("cannot access file %s", config -> stats_file);

				if (getrusage(RUSAGE_SELF, &usage) == -1)
					error_exit("getrusage() failed");

				proc_usage = (double)usage.ru_utime.tv_sec + (double)usage.ru_utime.tv_usec / 1000000.0 +
					(double)usage.ru_stime.tv_sec + (double)usage.ru_stime.tv_usec / 1000000.0;

				fprintf(fh, "%f %lld %lld %d %d %d %d %f %s\n", now, stats.total_recv, stats.total_sent,
						stats.total_recv_requests, stats.total_sent_requests,
						n_clients, total_n_bits, proc_usage, eb_output_scc -> stats());

				fclose(fh);
			}

			last_statistics_emit = now;
		}

		if (config -> ping_interval != 0 && ((last_ping + (double)config -> ping_interval) - now) <= 0)
		{
			for(loop=n_clients - 1; loop>=0; loop--)
			{
				if (do_client_send_ping_request(&clients[loop], config) == -1)
				{
					stats.disconnects++;

					forget_client(clients, &n_clients, loop);
				}
			}

			last_ping = now;
		}

		if (config -> kernelpool_filled_interval !=0 && ((last_kp_filled + (double)config -> kernelpool_filled_interval) - now) <= 0)
		{
			for(loop=n_clients - 1; loop>=0; loop--)
			{
				if (!clients[loop].is_server && do_client_kernelpoolfilled_request(&clients[loop], config) == -1)
				{
					stats.disconnects++;

					forget_client(clients, &n_clients, loop);
				}
			}

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

		if (rc > 0)
		{
			for(loop=n_clients - 1; loop>=0; loop--)
			{
				if (FD_ISSET(clients[loop].socket_fd, &rfds))
				{
					clients[loop].last_message = now;

					if (do_client(pools, n_pools, &clients[loop], &stats, config, eb_output_fips140, eb_output_scc) == -1)
					{
						dolog(LOG_INFO, "main|connection closed, removing client %s from list", clients[loop].host);
						dolog(LOG_DEBUG, "main|%s: %s, scc: %s", clients[loop].host, clients[loop].pfips140 -> stats(), clients[loop].pscc -> stats());

						stats.disconnects++;

						forget_client(clients, &n_clients, loop);
					}
				}
			}

			if (FD_ISSET(listen_socket_fd, &rfds))
			{
				struct sockaddr_in client_addr;
				socklen_t client_addr_len = sizeof(client_addr);
				int new_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);

				if (new_socket_fd != -1)
				{
					int dummy;

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
						n_clients++;

						clients = (client_t *)realloc(clients, n_clients * sizeof(client_t));
						if (!clients)
							error_exit("memory allocation error");

						memset(&clients[n_clients - 1], 0x00, sizeof(client_t));
						clients[n_clients - 1].socket_fd = new_socket_fd;
						dummy = sizeof(clients[n_clients - 1].host);
						snprintf(clients[n_clients - 1].host, dummy, "%s:%d", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);
						clients[n_clients - 1].pfips140 = new fips140();
						clients[n_clients - 1].pscc = new scc();
						clients[n_clients - 1].last_message = now;
						clients[n_clients - 1].connected_since = now;
						clients[n_clients - 1].last_put_message = now;
						clients[n_clients - 1].pfips140 -> set_user(clients[n_clients - 1].host);
						clients[n_clients - 1].pscc     -> set_user(clients[n_clients - 1].host);
						clients[n_clients - 1].pscc -> set_threshold(config -> scc_threshold);

						if (lookup_client_settings(&client_addr, &clients[n_clients - 1], config) == -1)
						{
							dolog(LOG_INFO, "main|client %s not found, terminating connection", clients[n_clients - 1].host);

							delete clients[n_clients - 1].pfips140;
							delete clients[n_clients - 1].pscc;

							n_clients--;

							close(new_socket_fd);
						}
					}
				}
			}
		}

		/* session time-outs */
		if (config -> communication_session_timeout > 0)
		{
			for(loop=n_clients - 1; loop>=0; loop--)
			{
				double time_left_in_session = (clients[loop].last_message + (double)config -> communication_session_timeout) - now;

				if (time_left_in_session <= 0.0)
				{
					dolog(LOG_INFO, "main|connection timeout, removing client %s from list", clients[loop].host);
					dolog(LOG_DEBUG, "%s: %s", clients[loop].host, clients[loop].pfips140 -> stats());

					stats.timeouts++;

					forget_client(clients, &n_clients, loop);
				}
			}
		}
	}

	dolog(LOG_WARNING, "main|end of main loop");
}
