int select_pool_with_enough_bits_available(pool **pools, int n_pools, int n_bits_to_read);
int get_bits_from_pools(int n_bits_requested, pool **pools, int n_pools, unsigned char **buffer, char allow_prng, char ignore_rngtest);
int find_non_full_pool(pool **pools, int n_pools);
int add_bits_to_pools(pool **pools, int n_pools, unsigned char *data, int n_bytes);
int get_bit_sum(pool **pools, int n_pools);
int add_event(pool **pools, int n_pools, double event);
char all_pools_full(pool **pools, int n_pools);
