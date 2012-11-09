// SVN: $Revision$
#define MIN_SLEEP 0.0001

class pools
{
private:
	std::vector<pool *> pool_vector;
	std::vector<std::string> cache_list;
	std::string cache_dir;
	unsigned int max_n_mem_pools;
	unsigned int max_n_disk_pools;
	unsigned int min_store_on_disk_n;
	bool disk_limit_reached_notified;
	bit_count_estimator *bce;
	int new_pool_size;

	pthread_rwlock_t list_lck;
	bool is_w_locked;

	unsigned int last_added_to;
	pthread_mutex_t lat_lck;

	void list_wlock();
	void list_wunlock();
	void list_rlock();
	void list_runlock();

	void load_cachefiles_list();
	bool load_caches(unsigned int load_n_bits, pool_crypto *pc);
	void store_caches(unsigned int keep_n);
	int select_pool_to_add_to(bool timed, double max_time, pool_crypto *pc);
	int find_non_full_pool(bool timed, double max_duration);
	void flush_empty_pools();
	void merge_pools(pool_crypto *pc);
	bool verify_quality(unsigned char *data, int n, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc);
	int get_bit_sum_unlocked(double max_duration);

public:
	pools(std::string cache_dir, unsigned int max_n_mem_pools, unsigned int max_n_disk_pools, unsigned int min_store_on_disk_n, bit_count_estimator *bce_in, int new_pool_size_in_bytes);
	~pools();

	int get_bits_from_pools(int n_bits_requested, unsigned char **buffer, bool allow_prng, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc, double max_duration, pool_crypto *pc);
	int add_bits_to_pools(unsigned char *data, int n_bytes, bool ignore_rngtest_fips140, fips140 *prt, bool ignore_rngtest_scc, scc *pscc, double max_duration, pool_crypto *pc);
	int get_bit_sum(double max_duration);
	int add_event(long double event, unsigned char *event_data, int n_event_data, double max_time, pool_crypto *pc);
	bool all_pools_full(double max_duration);
	int get_memory_pool_count();
	int get_disk_pool_count();
};
