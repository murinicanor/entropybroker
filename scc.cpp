#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "error.h"
#include "math.h"
#include "log.h"
#include "scc.h"

scc::scc()
{
	index = bytes_in = 0;

	memset(buffer, 0x00, sizeof buffer);

	threshold = 0.2;

	user = NULL;
}

scc::~scc()
{
	free(user);
}

void scc::set_user(char *puser)
{
	free(user);
        user = strdup(puser);
        if (!user)
                error_exit("memory allocation error");

        dolog(LOG_DEBUG, "registered scc-user %s", user);
}

void scc::set_threshold(double t)
{
	threshold = t;
}

void scc::add(unsigned char byte)
{
	buffer[index++] = byte;

	if (bytes_in < SCC_BUFFER_SIZE)
		bytes_in++;

	if (index >= SCC_BUFFER_SIZE)
		index = 0;
}

// 0: ok, -1: not ok
double scc::get_cur_scc()
{
	double scc_val;
	double prev_val = 0.0, u0 = 0.0;
	double t[3];
	int loop;

	if (bytes_in < 2)
		return 0;	// ok

	t[0] = t[1] = t[2] = 0.0;

	for(loop=0; loop<bytes_in; loop++)
	{
		double cur_val = (double)buffer[loop];

		if (loop == 0)
		{
			prev_val = 0;
			u0 = cur_val;
		}
		else
			t[0] += prev_val * cur_val;

		t[1] = t[1] + cur_val;
		t[2] = t[2] + (cur_val * cur_val);
		prev_val = cur_val;
	}

	t[0] = t[0] + prev_val * u0;
	t[1] = t[1] * t[1];
	scc_val = (double)bytes_in * t[2] - t[1];
	if (scc_val == 0.0)
		scc_val = -100000.0;
	else
		scc_val = ((double)bytes_in * t[0] - t[1]) / scc_val;

	return scc_val;
}

bool scc::is_ok()
{
	double cur_scc = fabs(get_cur_scc());
	bool rc = cur_scc < threshold;

	if (rc == false)
		dolog(LOG_WARNING, "SCC %f above threshold %f", cur_scc, threshold);

	return rc;
}

char *scc::stats()
{
	static char stats_buffer[4096];

	snprintf(stats_buffer, sizeof stats_buffer, "%f", get_cur_scc());

	return stats_buffer;
}
