// SVN: $Revision$
#include <stdio.h>
#include <pthread.h>
#include <string>
#include <math.h>
#include <vector>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "statistics.h"

double start_ts = get_ts();

double get_start_ts()
{
	return start_ts;
}

statistics::statistics()
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

int statistics::get_disconnects()
{
	my_mutex_lock(&disconnects_lck);
	int dummy = disconnects;
	my_mutex_unlock(&disconnects_lck);

	return dummy;
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

void statistics::put_history_login(hl_type_t hl_in, std::string host_in, std::string type_in, std::string user_in, double start_ts_in, double duration_in, std::string details_in)
{
	history_logins entry;

	entry.hl = hl_in;
	entry.host = host_in;
	entry.type = type_in;
	entry.user = user_in;
	entry.time_logged_in = start_ts_in;
	entry.duration = duration_in;
	entry.details = details_in;
	entry.event_ts = get_ts();

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

int statistics::get_reset_bps_cur()
{
	my_mutex_lock(&sent_lck);
	int dummy = bps_cur;
	bps_cur = 0;
	my_mutex_unlock(&sent_lck);

	return dummy;
}
