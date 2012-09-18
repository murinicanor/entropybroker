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
#include "utils.h"
#include "handle_client.h"
#include "statistics.h"

statistics::statistics(char *file_in, fips140 *fips140_in, scc *scc_in, pools *pp_in) : file(file_in), pfips140(fips140_in), pscc(scc_in), ppools(pp_in)
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

	start_ts = get_ts();
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

void statistics::inc_n_times_empty()
{
	n_times_empty++;
}

void statistics::inc_n_times_quota()
{
	n_times_quota++;
}

void statistics::inc_n_times_full()
{
	n_times_full++;
}

void statistics::track_sents(int cur_n_bits)
{
	bps_cur += cur_n_bits;
	total_sent += cur_n_bits;
	total_sent_requests++;
}

void statistics::track_recvs(int n_bits_added)
{
	total_recv += n_bits_added;
	total_recv_requests++;
}

void statistics::emit_statistics_file(int n_clients)
{
	FILE *fh = fopen(file, "a+");
	if (!fh)
		error_exit("cannot access file %s", file);

	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) == -1)
		error_exit("getrusage() failed");

	double proc_usage = (double)usage.ru_utime.tv_sec + (double)usage.ru_utime.tv_usec / 1000000.0 +
		(double)usage.ru_stime.tv_sec + (double)usage.ru_stime.tv_usec / 1000000.0;

	double now = get_ts();
	int total_n_bits = ppools -> get_bit_sum();
	fprintf(fh, "%f %lld %lld %d %d %d %d %f %s\n", now, stats -> total_recv, stats -> total_sent,
			stats -> total_recv_requests, stats -> total_sent_requests,
			n_clients, total_n_bits, proc_usage, scc -> stats());

	fclose(fh);
}

void statistics::emit_statistics_log(client_t *clients, int n_clients, bool force_stats)
{
	int total_n_bits = ppools -> get_bit_sum();
	double now = get_ts();
	double runtime = now - start_ts;

	if (!force_stats)
	{
		// FIXME locking
		for(int loop=0; loop<n_clients; loop++)
			clients[loop].bits_recv = clients[loop].bits_sent = 0;
	}

	bps = bps_cur / config -> reset_counters_interval;
	bps_cur = 0;

	dolog(LOG_DEBUG, "stats|client bps: %d (in last %ds interval), disconnects: %d", bps, config -> reset_counters_interval, disconnects);
	dolog(LOG_DEBUG, "stats|total recv: %ld (%fbps), total sent: %ld (%fbps), run time: %f", total_recv, double(total_recv) / runtime, total_sent, double(total_sent) / runtime, runtime);
	dolog(LOG_DEBUG, "stats|recv requests: %d, sent: %d, clients/servers: %d, bits: %d", total_recv_requests, total_sent_requests, n_clients, total_n_bits);
	dolog(LOG_DEBUG, "stats|%s, scc: %s", pfips140, pscc);
}
