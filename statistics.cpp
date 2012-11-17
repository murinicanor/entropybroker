// SVN: $Revision$
#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <math.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <arpa/inet.h>

#include "error.h"
#include "random_source.h"
#include "log.h"
#include "math.h"
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
	pthread_check(pthread_mutex_init(&msg_cnt_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&time_lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_mutex_init(&logins_lck, &global_mutex_attr), "pthread_mutex_init");

	bps_cur = 0;

	total_recv = total_recv_sd = total_recv_in = total_recv_in_sd = 0;
	total_sent = total_sent_sd = 0;
	total_recv_requests = 0;
	total_sent_requests = 0;
	n_times_empty = 0;
	n_times_not_allowed = 0;
	n_times_full = 0;
	n_times_quota = 0;

	disconnects = 0;
	timeouts = 0;

	msg_cnt = 0;
	last_message = last_put_message = last_get_message = connected_since = 0;

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
	pthread_check(pthread_mutex_destroy(&msg_cnt_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&time_lck), "pthread_mutex_destroy");
	pthread_check(pthread_mutex_destroy(&logins_lck), "pthread_mutex_destroy");
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
	total_sent_sd += cur_n_bits * cur_n_bits;
	total_sent_requests++;
	my_mutex_unlock(&sent_lck);
}

void statistics::track_recvs(int n_bits_added, int n_bits_in)
{
	my_mutex_lock(&recv_lck);
	total_recv += n_bits_added;
	total_recv_sd += n_bits_added * n_bits_added;
	total_recv_in += n_bits_in;
	total_recv_in_sd += n_bits_in * n_bits_in;
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
				n_clients, total_n_bits, proc_usage, pscc -> stats().c_str());
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

int statistics::get_times_empty()
{
	my_mutex_lock(&times_empty_lck);
	int dummy = n_times_empty;
	my_mutex_unlock(&times_empty_lck);

	return dummy;
}

int statistics::get_times_not_allowed()
{
	return 0; // FIXME
}

int statistics::get_times_full()
{
	my_mutex_lock(&times_full_lck);
	int dummy = n_times_full;
	my_mutex_unlock(&times_full_lck);

	return dummy;
}

int statistics::get_times_quota()
{
	my_mutex_lock(&times_quota_lck);
	int dummy = n_times_quota;
	my_mutex_unlock(&times_quota_lck);

	return dummy;
}

void statistics::get_recvs(long long int *total_bits, int *n_reqs, long long int *total_bits_in)
{
	my_mutex_lock(&recv_lck);

	*total_bits = total_recv;
	*total_bits_in = total_recv_in;
	*n_reqs = total_recv_requests;

	my_mutex_unlock(&recv_lck);
}

void statistics::get_sents(long long int *total_bits, int *n_sents)
{
	my_mutex_lock(&sent_lck);

	*total_bits = total_sent;
	*n_sents = total_sent_requests;

	my_mutex_unlock(&sent_lck);
}

void statistics::inc_msg_cnt()
{
	my_mutex_lock(&msg_cnt_lck);

	msg_cnt++;

	my_mutex_unlock(&msg_cnt_lck);
}

int statistics::get_msg_cnt()
{
	my_mutex_lock(&msg_cnt_lck);

	int dummy = msg_cnt;

	my_mutex_unlock(&msg_cnt_lck);

	return dummy;
}
void statistics::register_msg(bool is_put)
{
	double now = get_ts();

	my_mutex_lock(&time_lck);

	if (connected_since == 0)
		connected_since = now;

	last_message = now;

	if (is_put)
		last_put_message = now;
	else
		last_get_message = now;

	my_mutex_unlock(&time_lck);
}

double statistics::get_last_msg_ts()
{
	my_mutex_lock(&time_lck);
	double dummy = last_message;
	my_mutex_unlock(&time_lck);

	return dummy;
}

double statistics::get_since_ts()
{
	my_mutex_lock(&time_lck);
	double dummy = connected_since;
	my_mutex_unlock(&time_lck);

	return dummy;
}

double statistics::get_last_put_msg_ts()
{
	my_mutex_lock(&time_lck);
	double dummy = last_put_message;
	my_mutex_unlock(&time_lck);

	return dummy;
}

double statistics::get_last_get_msg_ts()
{
	my_mutex_lock(&time_lck);
	double dummy = last_get_message;
	my_mutex_unlock(&time_lck);

	return dummy;
}

double statistics::get_start_ts()
{
	// no locking; does not change
	return start_ts;
}

void statistics::put_history_login(std::string host_in, std::string type_in, std::string user_in, double start_ts_in, double duration_in)
{
	history_logins entry;

	entry.host = host_in;
	entry.type = type_in;
	entry.user = user_in;
	entry.time_logged_in = start_ts_in;
	entry.duration = duration_in;

	my_mutex_lock(&logins_lck);
	logins.push_back(entry);

	while(logins.size() > HISTORY_REMEMBER_N)
		logins.erase(logins.begin() + 0);

	my_mutex_unlock(&logins_lck);
}

std::vector<history_logins> statistics::get_login_history()
{
	my_mutex_lock(&logins_lck);
	std::vector<history_logins> result = logins;
	my_mutex_unlock(&logins_lck);

	return result;
}

void statistics::get_sent_avg_sd(double *avg, double *sd)
{
	*avg = double(total_sent) / double(total_sent_requests);

	*sd = sqrt((double(total_sent_sd) / double(total_sent_requests)) - pow(*avg, 2.0));
}

void statistics::get_recv_avg_sd(double *avg, double *sd)
{
	*avg = double(total_recv) / double(total_recv_requests);

	*sd = sqrt((double(total_recv_sd) / double(total_recv_requests)) - pow(*avg, 2.0));
}

void statistics::get_recv_in_avg_sd(double *avg, double *sd)
{
	*avg = double(total_recv_in) / double(total_recv_requests);

	*sd = sqrt((double(total_recv_in_sd) / double(total_recv_requests)) - pow(*avg, 2.0));
}
