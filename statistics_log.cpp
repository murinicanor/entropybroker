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
#include "encrypt_stream_blowfish.h"
#include "pool_crypto.h"
#include "pool.h"
#include "config.h"
#include "scc.h"
#include "pools.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"
#include "utils.h"
#include "auth.h"

void emit_statistics_file(std::string file, statistics *s, pools *ppools, scc *pscc, int n_clients)
{
	FILE *fh = fopen(file.c_str(), "a+");
	if (!fh)
		error_exit("cannot access file %s", file.c_str());

	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) == -1)
		error_exit("getrusage() failed");

	double proc_usage = double(usage.ru_utime.tv_sec) + double(usage.ru_utime.tv_usec) / 1000000.0 +
		double(usage.ru_stime.tv_sec) + double(usage.ru_stime.tv_usec) / 1000000.0;

	double now = get_ts();
	int total_n_bits = ppools -> get_bit_sum(1.0);

	long long int total_recv = 0, total_sent = 0, dummy;
	int total_recv_requests = 0, total_sent_requests = 0;
	s -> get_recvs(&total_recv, &total_recv_requests, &dummy);
	s -> get_sents(&total_sent, &total_sent_requests);

	fprintf(fh, "%f %lld %lld %d %d %d %d %f %s\n", now, total_recv, total_sent,
			total_recv_requests, total_sent_requests,
			n_clients, total_n_bits, proc_usage, pscc -> stats().c_str());

	fclose(fh);
}

void emit_statistics_log(statistics *s, int n_clients, bool force_stats, int reset_counters_interval, pools *ppools, fips140 *pfips140, scc *pscc)
{
	int total_n_bits = ppools -> get_bit_sum(1.0);
	double now = get_ts();
	double runtime = now - start_ts;

	long long int total_recv = 0, total_sent = 0, dummy;
	int total_recv_requests = 0, total_sent_requests = 0;
	s -> get_recvs(&total_recv, &total_recv_requests, &dummy);
	s -> get_sents(&total_sent, &total_sent_requests);

	int bps = s -> get_reset_bps_cur() / reset_counters_interval;

	dolog(LOG_DEBUG, "stats|client bps: %d (in last %ds interval), disconnects: %d", bps, reset_counters_interval, s -> get_disconnects());
	dolog(LOG_DEBUG, "stats|total recv: %ld (%fbps), total sent: %ld (%fbps), run time: %f", total_recv, double(total_recv) / runtime, total_sent, double(total_sent) / runtime, runtime);
	dolog(LOG_DEBUG, "stats|recv requests: %d, sent: %d, clients/servers: %u, bits: %d", total_recv_requests, total_sent_requests, n_clients, total_n_bits);
	dolog(LOG_DEBUG, "stats|%s, scc: %s", pfips140, pscc);
}
