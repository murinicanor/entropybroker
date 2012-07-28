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

	void load_cachefiles_list();
	void load_caches(unsigned int load_n_bits);
	void store_caches(unsigned int keep_n);
	int select_pool_to_add_to();
	int find_non_full_pool();

public:
	pools(std::string cache_dir, unsigned int max_n_mem_pools, unsigned int max_n_disk_pools, unsigned int min_store_on_disk_n);
	~pools();

	int get_bits_from_pools(int n_bits_requested, unsigned char **buffer, char allow_prng, char ignore_rngtest_fips140, fips140 *prt, char ignore_rngtest_scc, scc *pscc);
	int add_bits_to_pools(unsigned char *data, int n_bytes, char ignore_rngtest_fips140, fips140 *prt, char ignore_rngtest_scc, scc *pscc);
	int get_bit_sum();
	int add_event(long double event, unsigned char *event_data, int n_event_data);
	bool all_pools_full();
};
