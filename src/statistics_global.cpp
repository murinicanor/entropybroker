#include <stdio.h>
#include <pthread.h>
#include <string>
#include <math.h>
#include <vector>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"

double start_ts = get_ts();

double get_start_ts()
{
	return start_ts;
}

statistics_global::statistics_global()
{
	pthread_check(pthread_mutex_init(&logins_lck, &global_mutex_attr), "pthread_mutex_init");
}

statistics_global::~statistics_global()
{
	pthread_check(pthread_mutex_destroy(&logins_lck), "pthread_mutex_destroy");
}

void statistics_global::put_history_log(hl_type_t hl_in, std::string host_in, std::string type_in, std::string user_in, double start_ts_in, double duration_in, std::string details_in)
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

std::vector<history_logins> statistics_global::get_login_history()
{
	my_mutex_lock(&logins_lck);
	std::vector<history_logins> result = logins;
	my_mutex_unlock(&logins_lck);

	return result;
}
