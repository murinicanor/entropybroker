#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "error.h"
#include "pool.h"
#include "utils.h"
#include "fips140.h"
#include "scc.h"
#include "handle_pool.h"

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

int get_bits_from_pools(int n_bits_requested, pool **pools, int n_pools, unsigned char **buffer, char allow_prng, char ignore_rngtest_fips140, fips140 *pfips, char ignore_rngtest_scc, scc *pscc)
{
	int loop;
	int n_to_do_bytes = (n_bits_requested + 7) / 8;
	int n_to_do_bits = n_to_do_bytes * 8;
	int n_bits_retrieved = 0;
	unsigned char *cur_p;

	cur_p = *buffer = (unsigned char *)malloc(n_to_do_bytes + 1);
	if (!cur_p)
		error_exit("transmit_bits_to_client memory allocation failure");

	for(loop=0; loop<n_pools; loop++)
	{
		int pool_block_size = pools[loop] -> get_get_size();

		while(pools[loop] -> get_n_bits_in_pool() > pool_block_size)
		{
			int rngtest_loop, rc_fips140 = 0, rc_scc = 0;
			int cur_n_to_get_bits = min(n_to_do_bits, pool_block_size);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;
			int got_n_bytes, got_n_bits;

			got_n_bytes = pools[loop] -> get_entropy_data(cur_p, cur_n_to_get_bytes, 0);
			got_n_bits = got_n_bytes * 8;

			for(rngtest_loop=0; rngtest_loop<got_n_bytes; rngtest_loop++)
			{
				pfips -> add(cur_p[rngtest_loop]);
				pscc -> add(cur_p[rngtest_loop]);
			}

			if (!ignore_rngtest_fips140)
				rc_fips140 = pfips -> is_ok();
			if (!ignore_rngtest_scc)
				rc_scc = pfips -> is_ok();
			if (rc_fips140 == 0 && rc_scc == 0)
			{
				cur_p += got_n_bytes;
				n_to_do_bits -= got_n_bits;
				n_bits_retrieved += got_n_bits;
			}

			if (n_to_do_bits < 0)
				error_exit("overflow3");
			if (n_to_do_bits == 0)
				return n_bits_retrieved;
		}
	}

	if (allow_prng)
	{
		int index = 0;

		do
		{
			int rngtest_loop, rc_fips140 = 0, rc_scc = 0;
			int cur_n_to_get_bits = min(pools[index] -> get_pool_size(), n_to_do_bits);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;
			int got_n_bits, got_n_bytes;

			got_n_bytes = pools[index] -> get_entropy_data(cur_p, cur_n_to_get_bytes, 1);
			got_n_bits = got_n_bytes * 8;

			for(rngtest_loop=0; rngtest_loop<got_n_bytes; rngtest_loop++)
			{
				pfips -> add(cur_p[rngtest_loop]);
				pscc -> add(cur_p[rngtest_loop]);
			}

			if (!ignore_rngtest_fips140)
				rc_fips140 = pfips -> is_ok();
			if (!ignore_rngtest_scc)
				rc_scc = pfips -> is_ok();
			if (rc_fips140 == 0 && rc_scc == 0)
			{
				cur_p += got_n_bytes;
				n_to_do_bits -= got_n_bits;
				n_bits_retrieved += got_n_bits;
			}

			index++;
			if (index == n_pools)
				index = 0;
		}
		while(n_to_do_bits > 0);
	}

	return n_bits_retrieved;
}

int find_non_full_pool(pool **pools, int n_pools)
{
	int loop;

	for(loop=0; loop<n_pools; loop++)
	{
		if (! pools[loop] -> is_full())
			return loop;
	}

	return -1;
}

int add_bits_to_pools(pool **pools, int n_pools, unsigned char *data, int n_bytes, char ignore_rngtest_fips140, fips140 *pfips, char ignore_rngtest_scc, scc *pscc)
{
	int index;
	int n_bits_added = 0;

	if ((index = find_non_full_pool(pools, n_pools)) == -1)
		index = myrand(n_pools);

	while(n_bytes > 0)
	{
		int rngtest_loop, rc_fips140 = 0, rc_scc = 0;
		int n_bytes_to_add = min(8, n_bytes);
		unsigned char buffer[8];

		memcpy(buffer, data, n_bytes_to_add);

		for(rngtest_loop=0; rngtest_loop<n_bytes_to_add; rngtest_loop++)
		{
			pfips -> add(buffer[rngtest_loop]);
			pscc -> add(buffer[rngtest_loop]);
		}

		if (!ignore_rngtest_fips140)
			rc_fips140 = pfips -> is_ok();
		if (!ignore_rngtest_scc)
			rc_scc = pfips -> is_ok();
		if (rc_fips140 == 0 && rc_scc == 0)
		{
			n_bits_added += pools[index] -> add_entropy_data(buffer);
		}

		n_bytes -= n_bytes_to_add;
		data += n_bytes_to_add;

		if (pools[index] -> is_full())
		{
			if ((index = find_non_full_pool(pools, n_pools)) == -1)
				index = myrand(n_pools);
		}
	}

	return n_bits_added;
}

int get_bit_sum(pool **pools, int n_pools)
{
	int bit_count = 0;
	int loop;

	for(loop=0; loop<n_pools; loop++)
	{
		bit_count += pools[loop] -> get_n_bits_in_pool();
	}

	return bit_count;
}

int add_event(pool **pools, int n_pools, double event, unsigned char *event_data, int n_event_data)
{
	int index;

	if ((index = find_non_full_pool(pools, n_pools)) == -1)
		index = myrand(n_pools);

	return pools[index] -> add_event(event, event_data, n_event_data);
}

char all_pools_full(pool **pools, int n_pools)
{
	int loop;

	for(loop=0; loop<n_pools; loop++)
	{
		if (!pools[loop] -> is_full())
			return 0;
	}

	return 1;
}
