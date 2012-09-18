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
#include <openssl/sha.h>
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
#include "hc_protocol.h"

extern const char *pid_file;

int do_client(pools *ppools, client_t *client, statistics *stats, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc, bool *no_bits, bool *new_bits, bool *is_full, users *user_map)
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

		return do_client_get(ppools, client, stats, config, eb_output_fips140, eb_output_scc, no_bits);
	}
	else if (strcmp(cmd, "0002") == 0)	// PUT bits
	{
		return do_client_put(ppools, client, stats, config, new_bits, is_full);
	}
	else if (strcmp(cmd, "0003") == 0)	// server type
	{
		client -> is_server = 1;
		return do_client_server_type(client, config);
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
	else if (strcmp(cmd, "0011") == 0)	// proxy auth
	{
		return do_proxy_auth(client, config, user_map);
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

	free(clients[nr].password);

	n_to_move = (*n_clients - nr) - 1;
	if (n_to_move > 0)
		memmove(&clients[nr], &clients[nr + 1], sizeof(client_t) * n_to_move);
	(*n_clients)--;
}

void notify_servers_full(client_t *clients, int *n_clients, statistics *stats, config_t *config)
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

			stats -> inc_disconnects();

			forget_client(clients, n_clients, loop);
		}
	}
}

void notify_clients_data_available(client_t *clients, int *n_clients, statistics *stats, pools *ppools, config_t *config)
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

			stats -> inc_disconnects();

			forget_client(clients, n_clients, loop);
		}
	}
}

void notify_servers_data_needed(client_t *clients, int *n_clients, statistics *stats, config_t *config)
{
	for(int loop=*n_clients - 1; loop>=0; loop--)
	{
		if (!clients[loop].is_server)
			continue;

		if (send_need_data(clients[loop].socket_fd, config) == -1)
		{
			dolog(LOG_INFO, "main|connection closed, removing client %s from list", clients[loop].host);
			dolog(LOG_DEBUG, "main|%s: %s, scc: %s", clients[loop].host, clients[loop].pfips140 -> stats(), clients[loop].pscc -> stats());

			stats -> inc_disconnects();

			forget_client(clients, n_clients, loop);
		}
	}
}

void process_timed_out_cs(config_t *config, client_t *clients, int *n_clients, statistics *stats)
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

				stats -> inc_timeouts();

				forget_client(clients, n_clients, loop);
			}
		}
	}
}

int lookup_client_settings(struct sockaddr_in *client_addr, client_t *client, config_t *config)
{
	// FIXME

	return 0;
}

int send_pipe_command(int fd, unsigned char command)
{
}

void * thread(void *data)
{
	client_t *p = (client_t *)data;
	for(;;)
	{
		long long unsigned int auth_rnd = 1;
		std::string password;
		bool ok = auth_eb(socket_fd, p -> config -> communication_timeout, user_map, password, &auth_rnd) == 0;

		if (!ok)
		{
			dolog(LOG_WARNING, "main|client: %s/fd %d authentication failed", p -> host, socket_fd);
			break;
		}

		if (p -> config -> disable_nagle)
			disable_nagle(new_socket_fd);

		if (p -> config -> enable_keepalive)
			enable_tcp_keepalive(new_socket_fd);

		p -> challenge = auth_rnd;
		p -> ivec_counter = 0;
		calc_ivec((char *)password.c_str(), p -> challenge, p -> ivec_counter, p -> ivec);

		p -> password = strdup(password.c_str());
		BF_set_key(&p -> key, password.length(), (unsigned char *)password.c_str());


		// FIXME
// SELECT met timeout

		break;
	}

	close(new_socket_fd);
	close(to_thread[0]);
	close(to_thread[1]);
	close(to_main[0]);
	close(to_main[1]);

	return NULL;
}

void register_new_client(int listen_socket_fd, client_t **clients, int *n_clients, users *user_map, config_t *config, pools *ppools)
{
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int new_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);

	if (new_socket_fd != -1)
	{
		dolog(LOG_INFO, "main|new client: %s:%d (fd: %d)", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, new_socket_fd);

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

		strcpy(p -> type, "?");

		p -> max_bits_per_interval = config -> default_max_bits_per_interval;
		p -> ignore_rngtest_fips140 = config -> ignore_rngtest_fips140;
		p -> ignore_rngtest_scc = config -> ignore_rngtest_scc;
		p -> allow_prng = config -> allow_prng;

		// globals
		p -> pu = user_map;
		p -> config = config;
		p -> ppools = ppools;

		if (pipe(p -> to_thread) == -1)
			error_exit("Error creating pipes");
		if (pipe(p -> to_main) == -1)
			error_exit("Error creating pipes");

		if (pthread_create(&p -> th, NULL, thread, p) != 0)
			error_exit("Error creating thread");
	}
}

void main_loop(pools *ppools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc)
{
	client_t *clients = NULL;
	int n_clients = 0;
	double last_counters_reset = get_ts();
	double last_statistics_emit = get_ts();
	event_state_t event_state;
	int listen_socket_fd = start_listen(config -> listen_adapter, config -> listen_port, config -> listen_queue_size);
	statistics stats(config -> stats_file);
	double start_ts = get_ts();

	memset(&event_state, 0x00, sizeof(event_state));

	dolog(LOG_INFO, "main|main-loop started");

	users *user_map = new users(*config -> user_map);

	bool no_bits = false, new_bits = false, prev_is_full = false;
	for(;;)
	{
		int loop, rc;
		fd_set rfds;
		double now = get_ts();
		struct timespec tv;
		int max_fd = 0;
		double time_left = 300.0, dummy1_time;
		bool force_stats = false;
		sigset_t sig_set;

		if (sigemptyset(&sig_set) == -1)
			error_exit("sigemptyset");

		FD_ZERO(&rfds);

		dummy1_time = max(0, (last_statistics_emit + config -> statistics_interval) - now);
		time_left = min(time_left, dummy1_time);
		dummy1_time = max(0, (last_counters_reset + config -> reset_counters_interval) - now);
		time_left = min(time_left, dummy1_time);

		for(loop=0; loop<n_clients; loop++)
		{
			FD_SET(clients[loop].socket_fd, &rfds);
			max_fd = max(max_fd, clients[loop].socket_fd);
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
			user_map -> reload();
			force_stats = true;
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

		if (force_stats)
		{
			for(loop=0; loop<n_clients; loop++)
				dolog(LOG_DEBUG, "stats|%s (%s): %s, scc: %s | sent: %d, recv: %d | last msg: %ld seconds ago, %lds connected",
						clients[loop].host, clients[loop].type, clients[loop].pfips140 -> stats(),
						clients[loop].pscc -> stats(),
						clients[loop].bits_sent, clients[loop].bits_recv, (long int)(now - clients[loop].last_message), (long int)(now - clients[loop].connected_since));
		}

		if (rc == 0)
			continue;

		if (FD_ISSET(listen_socket_fd, &rfds))
			register_new_client(listen_socket_fd, &clients, &n_clients, user_map, config);
	}

	dolog(LOG_WARNING, "main|end of main loop");
}
