typedef struct
{
	int to_thread[2], to_main[2];
	pthread_t th;

	int socket_fd;
	char host[128], type[128];
	bool is_server;
	int max_bits_per_interval;
	bool allow_prng;
	bool ignore_rngtest_fips140, ignore_rngtest_scc;
	double last_message, last_put_message;
	double connected_since;
	char *password;

	fips140 *pfips140;
	scc *pscc;

	unsigned char ivec[8]; // used for data encryption
	int ivec_offset;
	long long unsigned int challenge;
	long long unsigned int ivec_counter; // required for CFB
	BF_KEY key;

	int bits_sent, bits_recv;
	pthread_mutex_t stats_lck;

	int ping_nr;

	// globals
	users *pu;
	config_t *config;
	pools *ppools;
} client_t;

void main_loop(pools *ppools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc);
