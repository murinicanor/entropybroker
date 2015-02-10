#include <stdio.h>
#include <pthread.h>
#include <string>
#include <math.h>
#include <vector>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "statistics.h"
#include "statistics_user.h"

statistics_user::statistics_user()
{
	connected_since = 0;
}

void statistics_user::register_msg(bool is_put)
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
