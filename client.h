typedef struct
{
	int socket_fd;
	char host[128];
	int bits_sent, bits_recv;
	int max_bits_per_interval;
	char allow_prng;
} client_t;

typedef struct
{
	int bps, bps_cur;

	long long int total_recv, total_sent;
	int total_recv_requests, total_sent_requests;
	int n_times_empty, n_times_not_allowed, n_times_full, n_times_quota;
} statistics_t;

void main_loop(pool **pools, int n_pools, int reset_counters_interval, char *adapter, int port);
