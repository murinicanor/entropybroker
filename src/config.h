typedef struct
{
	unsigned int max_number_of_mem_pools;
	unsigned int max_number_of_disk_pools;
	unsigned int min_store_on_disk_n;
	int pool_size_bytes;

	const char *listen_adapter;
	int listen_port;
	int listen_queue_size;
	bool disable_nagle;
	bool enable_keepalive;

	int reset_counters_interval;
	int statistics_interval;
	int ping_interval;
	int kernelpool_filled_interval;

	bit_count_estimator_type_t bitcount_estimator;

	char *stats_file;

	double communication_timeout;
	double communication_session_timeout;
	int default_sleep_time_when_pools_full;
	int default_sleep_when_pools_empty;
	int default_max_sleep_when_pools_empty;
	int when_pools_full_allow_submit_interval;

	int default_max_bits_per_interval;

	int max_open_files;

	bool ignore_rngtest_fips140, ignore_rngtest_scc;
	double scc_threshold;

	bool allow_event_entropy_addition;
	bool add_entropy_even_if_all_full;
	bool allow_prng;

	char *prng_seed_file;

	int max_get_put_size;

	int default_max_get_bps;

	hasher_type ht;
	stirrer_type st;
	random_source_t rs;

	std::string stream_cipher, mac_hasher, hash_hasher;

	std::string *user_map;

	const char *graph_font;

	std::string webserver_interface;
	int webserver_port;
} config_t;

void load_config(const char *config, config_t *pconfig);
