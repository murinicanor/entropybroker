#include "statistics.h"

statistics::statistics(char *file_in) : file(file_in)
{
	pthread_mutex_init(&lck, NULL);

	bps = 0;
	bps_cur = 0;

	total_recv = 0;
	total_sent = 0;
	total_recv_requests = 0;
	total_sent_requests = 0;
	n_times_empty = 0;
	n_times_not_allowed = 0;
	n_times_full = 0;
	n_times_quota = 0;

	disconnects = 0;
	timeouts = 0;
}

statistics::~statistics()
{
	pthread_mutex_destroy(&lck);
}

void statistics::inc_disconnects()
{
	disconnects++;
}

void statistics::inc_timeouts()
{
	timeouts++;
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
