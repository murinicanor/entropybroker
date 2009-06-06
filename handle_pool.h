int select_pool_with_enough_bits_available(pool **pools, int n_pools, int n_bits_to_read);
int get_bits_from_pools(int n_bits_requested, pool **pools, int n_pools, unsigned char **buffer, char allow_prng);
int add_bits_to_pools(pool **pools, int n_pools, unsigned char *data, int n_bytes);
