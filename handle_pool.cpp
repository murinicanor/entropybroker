#include <stdlib.h>

#include "error.h"
#include "pool.h"
#include "utils.h"

int select_pool_with_enough_bits_available(pool **pools, int n_pools, int n_bits_to_read)
{
	int max_n_bits = -1, max_n_bits_index = -1;
	int loop;

	for(loop=0; loop<n_pools; loop++)
	{
		int cur_n_bits = pools[loop] -> get_n_bits_in_pool();

		if (cur_n_bits >= n_bits_to_read)
		{
			return loop;
		}

		if (cur_n_bits >= max_n_bits)
		{
			max_n_bits = cur_n_bits;
			max_n_bits_index = loop;
		}
	}

	return max_n_bits_index;
}

int get_bits_from_pools(int n_bits_requested, pool **pools, int n_pools, unsigned char **buffer, char allow_prng)
{
	int loop;
	int n_to_do_bytes = (n_bits_requested + 7) / 8;
	int n_to_do_bits = n_to_do_bytes * 8;
	unsigned char *cur_p;

	cur_p = *buffer = (unsigned char *)malloc(n_to_do_bytes);
	if (!cur_p)
		error_exit("transmit_bits_to_client memory allocation failure");

	for(loop=0; loop<n_pools; loop++)
	{
		int cur_n_to_get_bits = min(n_to_do_bits, pools[loop] -> get_n_bits_in_pool()), cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

		pools[loop] -> get_entropy_data(cur_p, cur_n_to_get_bytes, 0);
		cur_p += cur_n_to_get_bytes;

		n_to_do_bits -= cur_n_to_get_bits;

		if (n_to_do_bits == 0)
			return n_bits_requested;
	}

	if (allow_prng)
	{
		int index = 0;

		do
		{
			int cur_n_to_get_bits = min(pools[index] -> get_pool_size(), n_to_do_bits);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

			pools[index] -> get_entropy_data(cur_p, cur_n_to_get_bytes, 1);
			cur_p += cur_n_to_get_bytes;

			n_to_do_bits -= cur_n_to_get_bits;

			index++;
			if (index == n_pools)
				index = 0;
		}
		while(n_to_do_bits > 0);
	}

	return (n_bits_requested - n_to_do_bits);
}

int add_bits_to_pools(pool **pools, int n_pools, unsigned char *data, int n_bytes)
{
	int index = 0;
	char first_round = 1;

	while(n_bytes > 0)
	{
		int cur_n_bits_to_add, cur_n_bytes_to_add;

		if (first_round)
			cur_n_bits_to_add = pools[index] -> get_pool_size() - pools[index] -> get_n_bits_in_pool();
		else
			cur_n_bits_to_add = 64;

		cur_n_bytes_to_add = min(8, (cur_n_bits_to_add + 7) / 8);

		pools[index] -> add_entropy_data(data);

		n_bytes -= cur_n_bytes_to_add;
		data += cur_n_bytes_to_add;

		index++;
		if (index == n_pools)
		{
			index = 0;
			first_round = 0;
		}
	}

	return 0;
}
