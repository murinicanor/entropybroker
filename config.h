typedef struct
{
	int number_of_pools;

	char *listen_adapter;
	int listen_port;
	int listen_queue_size;
	char disable_nagle;
	char enable_keepalive;

	int reset_counters_interval;
	int statistics_interval;
	int ping_interval;
	int kernelpool_filled_interval;

	char *stats_file;

	int communication_timeout;
	int communication_session_timeout;
	int default_sleep_time_when_pools_fool;
	int default_max_sleep_when_pool_fool;
	int default_sleep_when_pools_empty;
	int default_max_sleep_when_pools_empty;
	int when_pools_full_allow_submit_interval;

	int default_max_bits_per_interval;

	char ignore_rngtest_fips140, ignore_rngtest_scc;
	double scc_threshold;

	char allow_event_entropy_addition;
	char add_entropy_even_if_all_full;
	char allow_prng;

	char *auth_password;
} config_t;

void load_config(const char *config, config_t *pconfig);
