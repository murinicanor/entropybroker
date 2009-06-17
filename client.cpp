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
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "error.h"
#include "log.h"
#include "pool.h"
#include "rngtest.h"
#include "client.h"
#include "handle_pool.h"
#include "utils.h"

#define DEFAULT_SLEEP_WHEN_POOLS_FULL 10
#define DEFAULT_SLEEP_WHEN_POOLS_EMPTY 1
#define DEFAULT_MAX_SLEEP_WHEN_POOL_FULL 60
#define DEFAULT_COMM_TO 15

int send_denied_empty(int fd, statistics_t *stats)
{
	int seconds = DEFAULT_SLEEP_WHEN_POOLS_EMPTY;
	char buffer[4+4+1];

	stats -> n_times_empty++;

	// FIXME seconds = ... depending on stats

	snprintf(buffer, sizeof(buffer), "9000%04d", seconds);

	return WRITE_TO(fd, buffer, 8, DEFAULT_COMM_TO) == 8 ? 0 : -1;
}

int send_denied_quota(int fd, statistics_t *stats, int reset_counters_interval)
{
	char buffer[4+4+1];

	stats -> n_times_quota++;

	snprintf(buffer, sizeof(buffer), "9002%04d", reset_counters_interval);

	return WRITE_TO(fd, buffer, 8, DEFAULT_COMM_TO) == 8 ? 0 : -1;
}

int send_denied_full(client_t *client, pool **pools, int n_pools, statistics_t *stats)
{
	char buffer[4+4+1];
	int seconds = DEFAULT_SLEEP_WHEN_POOLS_FULL;

	stats -> n_times_full++;

	if (stats -> bps != 0)
	{
		// determine how many seconds it'll take before the current pool is empty
		int n_bits_in_pool = get_bit_sum(pools, n_pools);
		seconds = min(DEFAULT_MAX_SLEEP_WHEN_POOL_FULL, max(1, (n_bits_in_pool * 0.75) / max(1, stats -> bps)));
	}

	sprintf(buffer, "9001%04d", seconds);
	dolog(LOG_INFO, "%s all pools full, sleep of %d seconds", client -> host, seconds);

	if (WRITE_TO(client -> socket_fd, buffer, 8, DEFAULT_COMM_TO) != 8)
		return -1;

	return 0;
}

int do_client_get(pool **pools, int n_pools, client_t *client, statistics_t *stats, int reset_counters_interval)
{
	unsigned char *buffer, *ent_buffer;
	int cur_n_bits, cur_n_bytes;
	int transmit_size;
	char n_bits[4 + 1];
	n_bits[4] = 0x00;

	if (READ_TO(client -> socket_fd, n_bits, 4, DEFAULT_COMM_TO) != 4)
	{
		dolog(LOG_INFO, "%s short read while retrieving number of bits to send", client -> host);
		return -1;
	}

	cur_n_bits = atoi(n_bits);
	if (cur_n_bits == 0)
	{
		dolog(LOG_INFO, "%s 0 bits requested", client -> host);
		return -1;
	}
	if (cur_n_bits > 9992)
	{
		dolog(LOG_WARNING, "%s client requested more than 9992 bits: %d", client -> host, cur_n_bits);
		return -1;
	}

	dolog(LOG_DEBUG, "%s requested %d bits", client -> host, cur_n_bits);

	cur_n_bits = min(cur_n_bits, client -> max_bits_per_interval - client -> bits_sent);
	dolog(LOG_DEBUG, "%s is allowed to now receive %d bits", client -> host, cur_n_bits);
	if (cur_n_bits == 0)
		return send_denied_quota(client -> socket_fd, stats, reset_counters_interval); // FIXME: send_denied_quota
	if (cur_n_bits < 0)
		error_exit("cur_n_bits < 0");

	cur_n_bytes = (cur_n_bits + 7) / 8;

	dolog(LOG_DEBUG, "%s memory allocated, retrieving bits", client -> host);

	cur_n_bits = get_bits_from_pools(cur_n_bits, pools, n_pools, &ent_buffer, client -> allow_prng, client -> ignore_rngtest);
	if (cur_n_bits == 0)
	{
		dolog(LOG_WARNING, "%s no bits in pools", client -> host);
		free(ent_buffer);
		return send_denied_empty(client -> socket_fd, stats);
	}
	if (cur_n_bits < 0)
		error_exit("internal error: %d", cur_n_bits);
	cur_n_bytes = (cur_n_bits + 7) / 8;
	dolog(LOG_DEBUG, "got %d bits from pool", cur_n_bits);

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

	dolog(LOG_DEBUG, "%s transmit size: %d, msg: %s", client -> host, transmit_size, buffer);

	memcpy(&buffer[8], ent_buffer, cur_n_bytes);
	free(ent_buffer);

	if (WRITE_TO(client -> socket_fd, (char *)buffer, transmit_size, DEFAULT_COMM_TO) != transmit_size)
	{
		dolog(LOG_INFO, "%s error while sending to client", client -> host);
		free(buffer);
		return -1;
	}

	free(buffer);
}

int do_client_put(pool **pools, int n_pools, client_t *client, statistics_t *stats)
{
	if (all_pools_full(pools, n_pools))
	{
		char msg[4 + 4 + 1];
		int seconds = DEFAULT_SLEEP_WHEN_POOLS_FULL;
		char dummy_buffer[4];

		if (READ_TO(client -> socket_fd, dummy_buffer, 4, DEFAULT_COMM_TO) != 4)	// flush number of bits
			return -1;

		return send_denied_full(client, pools, n_pools, stats);
	}
	else
	{
		unsigned char *buffer;
		char msg[4+4+1];
		int cur_n_bits, cur_n_bytes;
		int n_bits_added;
		char n_bits[4 + 1];
		n_bits[4] = 0x00;

		if (READ_TO(client -> socket_fd, n_bits, 4, DEFAULT_COMM_TO) != 4)
		{
			dolog(LOG_INFO, "%s short read while retrieving number of bits to recv", client -> host);
			return -1;
		}

		cur_n_bits = atoi(n_bits);
		if (cur_n_bits == 0)
		{
			dolog(LOG_INFO, "%s 0 bits requested", client -> host);
			return -1;
		}
		if (cur_n_bits > 9992)
		{
			dolog(LOG_WARNING, "%s client requested more than 9992 bits: %d", client -> host, cur_n_bits);
			return -1;
		}

		sprintf(msg, "0001%04d", cur_n_bits);
		if (WRITE_TO(client -> socket_fd, msg, 8, DEFAULT_COMM_TO) != 8)
		{
			dolog(LOG_INFO, "%s short write while sending ack", client -> host);
			free(buffer);
			return -1;
		}

		cur_n_bytes = (cur_n_bits + 7) / 8;

		buffer = (unsigned char *)malloc(cur_n_bytes);
		if (!buffer)
			error_exit("%s error allocating %d bytes of memory", client -> host, cur_n_bytes);

		if (READ_TO(client -> socket_fd, (char *)buffer, cur_n_bytes, DEFAULT_COMM_TO) != cur_n_bytes)
		{
			dolog(LOG_INFO, "%s short read while retrieving entropy data", client -> host);
			free(buffer);
			return -1;
		}

		n_bits_added = add_bits_to_pools(pools, n_pools, buffer, cur_n_bytes);
		if (n_bits_added == -1)
			dolog(LOG_CRIT, "%s error while adding data to pools", client -> host);
		else
			dolog(LOG_DEBUG, "%s %d bits mixed into pools", client -> host, n_bits_added);

		client -> bits_recv += n_bits_added;
		stats -> total_recv += n_bits_added;
		stats -> total_recv_requests++;

		free(buffer);
	}
}

int do_client_server_type(pool **pools, int n_pools, client_t *client)
{
	char *buffer;
	int n_bits, n_bytes;
	char string_size[4 + 1];

	if (READ_TO(client -> socket_fd, string_size, 4, DEFAULT_COMM_TO) != 4)	// flush number of bits
		return -1;

	string_size[4] = 0x00;

	// this is a little odd but I wanted the meaning of the bytes
	// in the messages to be consistend, so not then bytes then bits,
	// no, always bits
	n_bits = atoi(string_size);
	n_bytes = (n_bits + 7) / 8;

	if (n_bytes <= 0)
		error_exit("%s sends 0003 msg with 0 bytes of contents", client -> host);

	buffer = (char *)malloc(n_bytes + 1);
	if (!buffer)
		error_exit("%s out of memory while allocating %d bytes", client -> host, n_bytes + 1);

	if (READ_TO(client -> socket_fd, buffer, n_bytes, DEFAULT_COMM_TO) != n_bytes)
	{
		free(buffer);
		dolog(LOG_INFO, "%s short read for 0003", client -> host);
		return -1;
	}

	buffer[n_bytes] = 0x00;

	dolog(LOG_INFO, "%s is \"%s\"", client -> host, buffer);

	free(buffer);

	return 0;
}

int do_client(pool **pools, int n_pools, client_t *client, statistics_t *stats, int reset_counters_interval)
{
	char cmd[4 + 1];
	cmd[4] = 0x00;

	if (READ_TO(client -> socket_fd, cmd, 4, DEFAULT_COMM_TO) != 4)
	{
		dolog(LOG_INFO, "%s short read while retrieving command", client -> host);
		return -1;
	}

	if (strcmp(cmd, "0001") == 0)		// GET bits
	{
		return do_client_get(pools, n_pools, client, stats, reset_counters_interval);
	}
	else if (strcmp(cmd, "0002") == 0)	// PUT bits
	{
		return do_client_put(pools, n_pools, client, stats);
	}
	else if (strcmp(cmd, "0003") == 0)	// server type
	{
		return do_client_server_type(pools, n_pools, client);
	}
	else
	{
		dolog(LOG_INFO, "%s command '%s'", client -> host, cmd);
		return 1;
	}

	dolog(LOG_DEBUG, "do_client: finished %s command for %s, pool bits: %d, client sent/recv: %d/%d", cmd, client -> host, get_bit_sum(pools, n_pools), client -> bits_sent, client -> bits_recv);

	return 0;
}

int lookup_client_settings(struct sockaddr_in *client_addr, client_t *client)
{
	// FIXME
	client -> max_bits_per_interval=16000000;
	client -> ignore_rngtest = 0;
}

void main_loop(pool **pools, int n_pools, int reset_counters_interval, char *adapter, int port, char *stats_file, rngtest_stats_t *rtst)
{
	client_t *clients = NULL;
	int n_clients = 0;
	double last_counters_reset = get_ts();
	double last_statistics_emit = get_ts();
	event_state_t event_state;
	int listen_socket_fd = start_listen(adapter, port);
	statistics_t	stats;
	double start_ts = get_ts();

	memset(&event_state, 0x00, sizeof(event_state));
	memset(&stats, 0x00, sizeof(stats));

	for(;;)
	{
		int event_bits;
		int loop, rc;
		fd_set rfds;
		double now = get_ts();
		struct timeval tv;
		int max_fd = 0;
		double time_left;

		FD_ZERO(&rfds);

		for(loop=0; loop<n_clients; loop++)
		{
			FD_SET(clients[loop].socket_fd, &rfds);
			max_fd = max(max_fd, clients[loop].socket_fd);
		}

		FD_SET(listen_socket_fd, &rfds);
		max_fd = max(max_fd, listen_socket_fd);

		time_left = max(0, min((last_statistics_emit + 300) - now, (last_counters_reset + reset_counters_interval) - now));
		tv.tv_sec = time_left;
		tv.tv_usec = (time_left - (double)tv.tv_sec) * 1000000.0;

		rc = select(max_fd + 1, &rfds, NULL, NULL, &tv);
		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			error_exit("select() failed");
		}

		now = get_ts();

		event_bits = add_event(pools, n_pools, now);
		dolog(LOG_DEBUG, "added %d bits of event-entropy to pool", event_bits);

		if (((last_counters_reset + (double)reset_counters_interval) - now) <= 0)
		{
			int total_n_bits = get_bit_sum(pools, n_pools);
			double runtime = now - start_ts;

			for(loop=0; loop<n_clients; loop++)
			{
				clients[loop].bits_recv = clients[loop].bits_sent = 0;
			}

			stats.bps = stats.bps_cur / reset_counters_interval;
			stats.bps_cur = 0;

			dolog(LOG_DEBUG, "client bps: %d (in last %ds interval), disconnects: %d", stats.bps, reset_counters_interval, stats.disconnects);
			dolog(LOG_DEBUG, "total recv: %ld (%fbps), total sent: %ld (%fbps), run time: %f", stats.total_recv, (double)stats.total_recv/runtime, stats.total_sent, (double)stats.total_sent/runtime, runtime);
			dolog(LOG_DEBUG, "recv requests: %d, sent: %d, clients/servers: %d, bits: %d", stats.total_recv_requests, stats.total_sent_requests, n_clients, total_n_bits);
			dolog(LOG_DEBUG, "%s", RNGTEST_stats());

			last_counters_reset = now;
		}

		if (((last_statistics_emit + 300.0) - now) <= 0)
		{
			if (stats_file)
			{
				double proc_usage;
				struct rusage usage;
				int total_n_bits = get_bit_sum(pools, n_pools);
				FILE *fh = fopen(stats_file, "a+");
				if (!fh)
					error_exit("cannot access file %s", stats_file);

				if (getrusage(RUSAGE_SELF, &usage) == -1)
					error_exit("getrusage() failed");

				proc_usage = (double)usage.ru_utime.tv_sec + (double)usage.ru_utime.tv_usec / 1000000.0 +
						(double)usage.ru_stime.tv_sec + (double)usage.ru_stime.tv_usec / 1000000.0;

				fprintf(fh, "%f %ld %ld %d %d %d %d %f\n", now, stats.total_recv, stats.total_sent,
									stats.total_recv_requests, stats.total_sent_requests,
									n_clients, total_n_bits, proc_usage);

				fclose(fh);
			}

			last_statistics_emit = now;
		}

		if (rc > 0)
		{
			for(loop=0; loop<n_clients; loop++)
			{
				if (FD_ISSET(clients[loop].socket_fd, &rfds))
				{
					if (do_client(pools, n_pools, &clients[loop], &stats, reset_counters_interval) == -1)
					{
						int n_to_move;

						dolog(LOG_INFO, "main_loop: removing client %s from list", clients[loop].host);

						stats.disconnects++;

						close(clients[loop].socket_fd);

						n_to_move = (n_clients - loop) - 1;
						if (n_to_move > 0)
							memmove(&clients[loop], &clients[loop + 1], sizeof(client_t) * n_to_move);
						n_clients--;

						break;
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

					dolog(LOG_INFO, "main_loop: new client: %s:%d", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);

					n_clients++;

					clients = (client_t *)realloc(clients, n_clients * sizeof(client_t));
					if (!clients)
						error_exit("memory allocation error");

					memset(&clients[n_clients - 1], 0x00, sizeof(client_t));
					clients[n_clients - 1].socket_fd = new_socket_fd;
					dummy = sizeof(clients[n_clients - 1].host);
					snprintf(clients[n_clients - 1].host, dummy, "%s:%d", inet_ntoa(client_addr.sin_addr), client_addr.sin_port);

					if (lookup_client_settings(&client_addr, &clients[n_clients - 1]) == -1)
					{
						dolog(LOG_INFO, "main_loop: client %s not found, terminating connection", clients[n_clients - 1].host);

						n_clients--;

						close(new_socket_fd);
					}
				}
			}
		}
	}

	dolog(LOG_WARNING, "main_loop: end of main loop?!");
}
