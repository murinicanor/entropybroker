class pools
{
private:
	std::vector<pool *> pool_vector;
	std::string cache_dir;

public:
	pools(int max_n_in, std::string cache_in);
	~pools();

	int select_pool_with_enough_bits_available(int n_bits_to_read);
	int get_bits_from_pools(int n_bits_requested, unsigned char **buffer, char allow_prng, char ignore_rngtest_fips140, fips140 *prt, char ignore_rngtest_scc, scc *pscc);
	int find_non_full_pool();
	int add_bits_to_pools(unsigned char *data, int n_bytes, char ignore_rngtest_fips140, fips140 *prt, char ignore_rngtest_scc, scc *pscc);
	int get_bit_sum();
	int add_event(long double event, unsigned char *event_data, int n_event_data);
	bool all_pools_full();
};
