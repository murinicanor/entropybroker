typedef struct
{
	int socket_fd;
	char host[128], type[128];
	char is_server;
	int bits_sent, bits_recv;
	int max_bits_per_interval;
	char allow_prng;
	char ignore_rngtest_fips140, ignore_rngtest_scc;
	double last_message, last_put_message;
	double connected_since;
	unsigned char ivec[8];

	fips140 *pfips140;
	scc *pscc;

	int ping_nr;
} client_t;

typedef struct
{
	int bps, bps_cur;

	long long int total_recv, total_sent;
	int total_recv_requests, total_sent_requests;
	int n_times_empty, n_times_not_allowed, n_times_full, n_times_quota;

	int disconnects, timeouts;
} statistics_t;

void main_loop(pool **pools, int n_pools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc);
