// SVN: $Revision$
#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>

#include "error.h"
#include "random_source.h"
#include "log.h"
#include "math.h"
#include "ivec.h"
#include "hasher.h"
#include "stirrer.h"
#include "fips140.h"
#include "hasher_type.h"
#include "stirrer_type.h"
#include "encrypt_stream.h"
#include "users.h"
#include "config.h"
#include "scc.h"
#include "pool_crypto.h"
#include "pool.h"
#include "pools.h"
#include "utils.h"
#include "statistics.h"
#include "handle_client.h"

statistics::statistics(char *file_in, fips140 *fips140_in, scc *scc_in, pools *pp_in) : file(file_in), pfips140(fips140_in), pscc(scc_in), ppools(pp_in)
{
	pthread_check(pthread_mutex_init(&recv_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&sent_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&times_empty_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&times_not_allowed_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&times_full_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&times_quota_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&disconnects_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&timeouts_lck, &global_mutex_attr), "pthread_mutex_init");

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
	pthread_check(pthread_mutex_destroy(&recv_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&sent_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&times_empty_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&times_not_allowed_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&times_full_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&times_quota_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&disconnects_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&timeouts_lck), "pthread_mutex_destroy");
}

void statistics::inc_disconnects()
{
	my_mutex_lock(&disconnects_lck);
	disconnects++;
	my_mutex_unlock(&disconnects_lck);
}

void statistics::inc_timeouts()
{
	my_mutex_lock(&timeouts_lck);
	timeouts++;
	my_mutex_unlock(&timeouts_lck);
}

void statistics::inc_n_times_empty()
{
	my_mutex_lock(&times_empty_lck);
	n_times_empty++;
	my_mutex_unlock(&times_empty_lck);
}

void statistics::inc_n_times_quota()
{
	my_mutex_lock(&times_quota_lck);
	n_times_quota++;
	my_mutex_unlock(&times_quota_lck);
}

void statistics::inc_n_times_full()
{
	my_mutex_lock(&times_full_lck);
	n_times_full++;
	my_mutex_unlock(&times_full_lck);
}

void statistics::track_sents(int cur_n_bits)
{
	my_mutex_lock(&sent_lck);
	bps_cur += cur_n_bits;
	total_sent += cur_n_bits;
	total_sent_requests++;
	my_mutex_unlock(&sent_lck);
}

void statistics::track_recvs(int n_bits_added)
{
	my_mutex_lock(&recv_lck);
	total_recv += n_bits_added;
	total_recv_requests++;
	my_mutex_unlock(&recv_lck);
}

void statistics::lock_all()
{
	my_mutex_lock(&recv_lck);
	my_mutex_lock(&sent_lck);
	my_mutex_lock(&times_empty_lck);
	my_mutex_lock(&times_not_allowed_lck);
	my_mutex_lock(&times_full_lck);
	my_mutex_lock(&times_quota_lck);
	my_mutex_lock(&disconnects_lck);
	my_mutex_lock(&timeouts_lck);
}

void statistics::unlock_all()
{
	my_mutex_unlock(&timeouts_lck);
	my_mutex_unlock(&disconnects_lck);
	my_mutex_unlock(&times_quota_lck);
	my_mutex_unlock(&times_full_lck);
	my_mutex_unlock(&times_not_allowed_lck);
	my_mutex_unlock(&times_empty_lck);
	my_mutex_unlock(&sent_lck);
	my_mutex_unlock(&recv_lck);
}

void statistics::emit_statistics_file(int n_clients)
{
	if (file)
	{
		FILE *fh = fopen(file, "a+");
		if (!fh)
			error_exit("cannot access file %s", file);

		struct rusage usage;
		if (getrusage(RUSAGE_SELF, &usage) == -1)
			error_exit("getrusage() failed");

		double proc_usage = double(usage.ru_utime.tv_sec) + double(usage.ru_utime.tv_usec) / 1000000.0 +
			double(usage.ru_stime.tv_sec) + double(usage.ru_stime.tv_usec) / 1000000.0;

		double now = get_ts();
		int total_n_bits = ppools -> get_bit_sum(1.0);

		lock_all();
		fprintf(fh, "%f %lld %lld %d %d %d %d %f %s\n", now, total_recv, total_sent,
				total_recv_requests, total_sent_requests,
				n_clients, total_n_bits, proc_usage, pscc -> stats());
		unlock_all();

		fclose(fh);
	}
}

void statistics::emit_statistics_log(int n_clients, bool force_stats, int reset_counters_interval)
{
	int total_n_bits = ppools -> get_bit_sum(1.0);
	double now = get_ts();
	double runtime = now - start_ts;

	lock_all();
	int bps = bps_cur / reset_counters_interval;
	bps_cur = 0;

	dolog(LOG_DEBUG, "stats|client bps: %d (in last %ds interval), disconnects: %d", bps, reset_counters_interval, disconnects);
	dolog(LOG_DEBUG, "stats|total recv: %ld (%fbps), total sent: %ld (%fbps), run time: %f", total_recv, double(total_recv) / runtime, total_sent, double(total_sent) / runtime, runtime);
	dolog(LOG_DEBUG, "stats|recv requests: %d, sent: %d, clients/servers: %u, bits: %d", total_recv_requests, total_sent_requests, n_clients, total_n_bits);
	dolog(LOG_DEBUG, "stats|%s, scc: %s", pfips140, pscc);
	unlock_all();
}
