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
#include "statistics.h"
#include "handle_client.h"
#include "utils.h"
#include "signals.h"
#include "auth.h"
#include "protocol.h"
#include "hc_protocol.h"

extern const char *pid_file;

void forget_client_index(std::vector<client_t *> *clients, int nr)
{
	client_t *p = clients -> at(nr);

	pthread_mutex_destroy(&p -> stats_lck);

	close(p -> socket_fd);

	close(p -> to_thread[1]);
	close(p -> to_main[0]);

	delete p -> pfips140;
	delete p -> pscc;

	free(p -> password);

	if (pthread_yield() != 0)
		error_exit("pthread_yield failed");

	pthread_cancel(p -> th);

	void *value_ptr = NULL;
	if (pthread_join(p -> th, &value_ptr) != 0)
		error_exit("pthread_join failed");

	delete p;
	clients -> erase(clients -> begin() + nr);
}

void forget_client_socket_fd(std::vector<client_t *> *clients, int socket_fd)
{
	for(unsigned int index=0; index<clients -> size(); index++)
	{
		if (clients -> at(index) -> socket_fd == socket_fd)
		{
			forget_client_index(clients, index);

			break;
		}
	}
}

void forget_client_thread_id(std::vector<client_t *> *clients, pthread_t *tid)
{
	for(unsigned int index=0; index<clients -> size(); index++)
	{
		if (pthread_equal(clients -> at(index) -> th, *tid) != 0)
		{
			forget_client_index(clients, index);

			break;
		}
	}
}

int send_pipe_command(int fd, unsigned char command)
{
	for(;;)
	{
		int rc = write(fd, &command, 1);

		if (rc == 0)
			return -1;

		if (rc == -1)
		{
			if (errno == EINTR)
				continue;

			return -1;
		}

		break;
	}

	return 0;
}

void * thread(void *data)
{
	client_t *p = (client_t *)data;

	for(;;)
	{
		long long unsigned int auth_rnd = 1;
		std::string password;
		bool ok = auth_eb(p -> socket_fd, p -> config -> communication_timeout, p -> pu, password, &auth_rnd) == 0;

		if (!ok)
		{
			dolog(LOG_WARNING, "main|client: %s/fd %d authentication failed", p -> host, p -> socket_fd);
			break;
		}

		if (p -> config -> disable_nagle)
			disable_nagle(p -> socket_fd);

		if (p -> config -> enable_keepalive)
			enable_tcp_keepalive(p -> socket_fd);

		p -> challenge = auth_rnd;
		p -> ivec_counter = 0;
		calc_ivec((char *)password.c_str(), p -> challenge, p -> ivec_counter, p -> ivec);

		p -> password = strdup(password.c_str());
		BF_set_key(&p -> key, password.length(), (unsigned char *)password.c_str());

		for(;;)
		{
			struct timeval tv;

			tv.tv_sec = p -> config -> communication_session_timeout;
			tv.tv_usec = (p -> config -> communication_session_timeout - double(tv.tv_sec)) * 1000000;

			int max_fd = -1;
			fd_set rfds;
			FD_ZERO(&rfds);

			FD_SET(p -> socket_fd, &rfds);
			max_fd = max(max_fd, p -> socket_fd);
			FD_SET(p -> to_thread[0], &rfds);
			max_fd = max(max_fd, p -> to_thread[0]);

			int rc = select(max_fd + 1, &rfds, NULL, NULL, &tv);
			if (rc == -1)
			{
				if (errno == EINTR)
					continue;

				dolog(LOG_CRIT, "select() failed for thread %s", p -> host);
				break;
			}
			else if (rc == 0)
			{
				dolog(LOG_CRIT, "host %s fell asleep", p -> host);
				break;
			}

			if (FD_ISSET(p -> socket_fd, &rfds))
			{
				bool no_bits = false, new_bits = false, is_full = false;

				if (do_client(p, &no_bits, &new_bits, &is_full) == -1)
				{
					dolog(LOG_INFO, "Terminating connection with %s", p -> host);
					break;
				}

				int rc_pipe = 0;
				if (p -> is_server)
				{

					if (new_bits)
						rc_pipe |= send_pipe_command(p -> to_main[1], PIPE_CMD_HAVE_DATA);
					if (is_full)
						rc_pipe |= send_pipe_command(p -> to_main[1], PIPE_CMD_IS_FULL);
				}
				else
				{
					if (no_bits)
						rc_pipe |= send_pipe_command(p -> to_main[1], PIPE_CMD_NEED_DATA);
				}

				if (rc_pipe)
				{
					dolog(LOG_CRIT, "Thread connection to main thread lost (1)");
					break;
				}
			}

			bool abort = false;
			bool need_data = false, have_data = false, is_full = false;
			do
			{
				unsigned char cmd = 0;

				int rc_pipe = read(p -> to_thread[0], &cmd, 1);
				if (rc_pipe == 0)
					break;
				if (rc_pipe == -1)
				{
					if (errno == EINTR)
						continue;

					if (errno == EAGAIN || errno == EWOULDBLOCK)
						break;

					dolog(LOG_CRIT, "Thread connection to main thread lost (2)");
					abort = true;
				}
				else
				{
					if (cmd == PIPE_CMD_NEED_DATA)
					{
						need_data = true;
						have_data = false;
						is_full = false;
					}
					else if (cmd == PIPE_CMD_HAVE_DATA || cmd == PIPE_CMD_IS_FULL)
					{
						need_data = false;
						have_data = true;

						if (cmd == PIPE_CMD_IS_FULL)
							is_full = true;
					}
					else
					{
						error_exit("Unknown interprocess command %02x", cmd);
					}
				}
			}
			while(!abort);

			if (abort)
				break;

			int rc_client = 0;
			if (need_data)
				rc_client |= notify_server_data_needed(p -> socket_fd, p -> stats, p -> config);

			if (have_data)
				rc_client |= notify_client_data_available(p -> socket_fd, p -> ppools, p -> stats, p -> config);

			if (is_full)
				rc_client |= notify_server_full(p -> socket_fd, p -> stats, p -> config);

			if (rc_client)
			{
				dolog(LOG_INFO, "Connection with %s lost", p -> host);

				break;
			}
		}

		dolog(LOG_DEBUG, "End of thread imminent");

		break;
	}

	close(p -> socket_fd);
	close(p -> to_thread[0]);
	close(p -> to_main[1]);

	dolog(LOG_DEBUG, "End of thread");

	return NULL;
}

void register_new_client(int listen_socket_fd, std::vector<client_t *> *clients, users *user_map, config_t *config, pools *ppools, statistics *stats, fips140 *output_fips140, scc *output_scc)
{
	struct sockaddr_in client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int new_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);

	if (new_socket_fd != -1)
	{
		dolog(LOG_INFO, "main|new client: %s:%d (fd: %d)", inet_ntoa(client_addr.sin_addr), client_addr.sin_port, new_socket_fd);

		client_t *p = new client_t;
		if (!p)
			error_exit("memory allocation error");

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

		pthread_mutex_init(&p -> stats_lck, NULL);

		// globals
		p -> pu = user_map;
		p -> config = config;
		p -> ppools = ppools;
		p -> stats = stats;
		p -> output_fips140 = output_fips140;
		p -> output_scc = output_scc;

		if (pipe(p -> to_thread) == -1)
			error_exit("Error creating pipes");

		set_fd_nonblocking(p -> to_thread[0]);

		if (pipe(p -> to_main) == -1)
			error_exit("Error creating pipes");

		set_fd_nonblocking(p -> to_main[0]);

		if (pthread_create(&p -> th, NULL, thread, p) != 0)
			error_exit("Error creating thread");

		clients -> push_back(p);
	}
}

int process_client(client_t *p, std::vector<msg_pair_t> *msgs_clients, std::vector<msg_pair_t> *msgs_servers)
{
	int rc = 0;

	for(;;)
	{
		unsigned char cmd = 0;

		int rc_pipe = read(p -> to_main[0], &cmd, 1);
		if (rc_pipe == 0)
			break;
		if (rc_pipe == -1)
		{
			if (errno == EINTR)
				continue;

			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			rc = -1;

			break;
		}

		msg_pair_t queue_entry = { p -> socket_fd, cmd };

		if (cmd == PIPE_CMD_HAVE_DATA)
			msgs_clients -> push_back(queue_entry);
		else if (cmd == PIPE_CMD_NEED_DATA)
			msgs_servers -> push_back(queue_entry);
		else if (cmd == PIPE_CMD_IS_FULL)
			msgs_servers -> push_back(queue_entry);
		else
			error_exit("Message %02x from thread %s/%s is not known", cmd, p -> host, p -> type);
	}

	return rc;
}

void send_to_clients_servers(std::vector<client_t *> *clients, std::vector<msg_pair_t> *msgs, bool is_server)
{
	for(unsigned int loop=0; loop<msgs -> size(); loop++)
	{
		for(unsigned int index=0; index<clients -> size(); index++)
		{
			if (clients -> at(index) -> is_server == is_server && clients -> at(index) -> socket_fd != msgs -> at(loop).fd_sender)
				(void)send_pipe_command(clients -> at(index) -> to_thread[1], msgs -> at(loop).cmd);
		}
	}
}

void main_loop(pools *ppools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc)
{
	std::vector<client_t *> clients;
	double last_counters_reset = get_ts();
	double last_statistics_emit = get_ts();
	event_state_t event_state;
	int listen_socket_fd = start_listen(config -> listen_adapter, config -> listen_port, config -> listen_queue_size);
	statistics stats(config -> stats_file, eb_output_fips140, eb_output_scc, ppools);

	memset(&event_state, 0x00, sizeof(event_state));

	dolog(LOG_INFO, "main|main-loop started");

	users *user_map = new users(*config -> user_map);

	for(;;)
	{
		fd_set rfds;
		double now = get_ts();
		struct timespec tv;
		int max_fd = -1;
		double time_left = 300.0, dummy1_time = -1.0;
		bool force_stats = false;
		sigset_t sig_set;

		if (sigemptyset(&sig_set) == -1)
			error_exit("sigemptyset");

		FD_ZERO(&rfds);

		dummy1_time = max(0, (last_statistics_emit + config -> statistics_interval) - now);
		time_left = min(time_left, dummy1_time);
		dummy1_time = max(0, (last_counters_reset + config -> reset_counters_interval) - now);
		time_left = min(time_left, dummy1_time);

		for(unsigned int loop =0; loop<clients.size(); loop++)
		{
			FD_SET(clients.at(loop) -> to_main[0], &rfds);
			max_fd = max(max_fd, clients.at(loop) -> to_main[0]);
		}

		FD_SET(listen_socket_fd, &rfds);
		max_fd = max(max_fd, listen_socket_fd);

		tv.tv_sec = time_left;
		tv.tv_nsec = (time_left - (double)tv.tv_sec) * 1000000000.0;

		int rc = pselect(max_fd + 1, &rfds, NULL, NULL, &tv, &sig_set);

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

		if (((last_counters_reset + (double)config -> reset_counters_interval) - now) <= 0 || force_stats)
		{
			stats.emit_statistics_log(clients.size(), force_stats, config -> reset_counters_interval);

			if (!force_stats)
			{
				for(unsigned int loop=0; loop<clients.size(); loop++)
				{
					client_t *p = clients.at(loop);

					pthread_mutex_lock(&p -> stats_lck);
					p -> bits_recv = p -> bits_sent = 0;
					pthread_mutex_unlock(&p -> stats_lck);
				}
			}

			last_counters_reset = now;
		}

		if ((config -> statistics_interval != 0 && ((last_statistics_emit + (double)config -> statistics_interval) - now) <= 0) || force_stats)
		{
			stats.emit_statistics_file(clients.size());

			last_statistics_emit = now;
		}

		if (force_stats)
		{
			for(unsigned int loop=0; loop<clients.size(); loop++)
			{
				client_t *p = clients.at(loop);
				pthread_mutex_lock(&p -> stats_lck);
				dolog(LOG_DEBUG, "stats|%s (%s): %s, scc: %s | sent: %d, recv: %d | last msg: %ld seconds ago, %lds connected",
						p -> host, p -> type, p -> pfips140 -> stats(),
						p -> pscc -> stats(),
						p -> bits_sent, p -> bits_recv, (long int)(now - p -> last_message), (long int)(now - p -> connected_since));
				pthread_mutex_unlock(&p -> stats_lck);
			}
		}

		if (rc == 0)
			continue;

		if (config -> allow_event_entropy_addition)
		{
			int event_bits = ppools -> add_event(now, (unsigned char *)&rfds, sizeof(rfds));

			dolog(LOG_DEBUG, "main|added %d bits of event-entropy to pool", event_bits);
		}

		std::vector<pthread_t *> delete_ids;
		std::vector<msg_pair_t> msgs_clients;
		std::vector<msg_pair_t> msgs_servers;
		for(unsigned int loop=0; loop<clients.size(); loop++)
		{
			if (!FD_ISSET(clients.at(loop) -> to_main[0], &rfds))
				continue;

			if (process_client(clients.at(loop), &msgs_clients, &msgs_servers) == -1)
				delete_ids.push_back(&clients.at(loop) -> th);
		}

		for(unsigned int loop=0; loop<delete_ids.size(); loop++)
			forget_client_thread_id(&clients, delete_ids.at(loop));

		send_to_clients_servers(&clients, &msgs_clients, false);
		send_to_clients_servers(&clients, &msgs_servers, true);

		if (FD_ISSET(listen_socket_fd, &rfds))
			register_new_client(listen_socket_fd, &clients, user_map, config, ppools, &stats, eb_output_fips140, eb_output_scc);
	}

	dolog(LOG_WARNING, "main|end of main loop");
}
