#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <vector>
#include <string>

#include "error.h"
#include "log.h"
#include "pool.h"
#include "utils.h"
#include "fips140.h"
#include "scc.h"
#include "pools.h"

pools::pools(int max_n_pools_in, std::string cache_dir_in)
{
	cache_dir = cache_dir_in;

	std::string global_dump_file = cache_dir + "/pools.dat";
	FILE *fh = fopen(global_dump_file.c_str(), "rb");
	if (!fh)
	{
		dolog(LOG_INFO, "No cache-file found, continuing...\n");

		for(int loop=0; loop<max_n_pools_in; loop++)
			pool_vector.push_back(new pool());
	}
	else
	{
		for(int loop=0; loop<max_n_pools_in; loop++)
			pool_vector.push_back(new pool(loop + 1, fh));

		fclose(fh);
	}
}

pools::~pools()
{
	std::string global_dump_file = cache_dir + "/pools.dat";
	FILE *fh = fopen(global_dump_file.c_str(), "wb");
	if (!fh)
		error_exit("Failed to create %s", global_dump_file.c_str());

	for(unsigned int index=0; index<pool_vector.size(); index++)
	{
		pool_vector.at(index) -> dump(fh);

		delete pool_vector.at(index);
	}

	fclose(fh);
}

int pools::select_pool_with_enough_bits_available(int n_bits_to_read)
{
	int max_n_bits = -1, max_n_bits_index = -1;

	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		int cur_n_bits = pool_vector.at(loop) -> get_n_bits_in_pool();

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

int pools::get_bits_from_pools(int n_bits_requested, unsigned char **buffer, char allow_prng, char ignore_rngtest_fips140, fips140 *pfips, char ignore_rngtest_scc, scc *pscc)
{
	int n_to_do_bytes = (n_bits_requested + 7) / 8;
	int n_to_do_bits = n_to_do_bytes * 8;
	int n_bits_retrieved = 0;
	unsigned char *cur_p;

	cur_p = *buffer = (unsigned char *)malloc(n_to_do_bytes + 1);
	if (!cur_p)
		error_exit("transmit_bits_to_client memory allocation failure");

	// FIXME if get_bit_sum() < n_bits_requested: load pools from disk
	// if get_bit_sum() < (POOL_SIZE * min_n_avail_pools): load pools from thisk

	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		int pool_block_size = pool_vector.at(loop) -> get_get_size();

		while(pool_vector.at(loop) -> get_n_bits_in_pool() > pool_block_size)
		{
			int rngtest_loop, rc_fips140 = 0, rc_scc = 0;
			int cur_n_to_get_bits = min(n_to_do_bits, pool_block_size);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;
			int got_n_bytes, got_n_bits;

			got_n_bytes = pool_vector.at(loop) -> get_entropy_data(cur_p, cur_n_to_get_bytes, 0);
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
		unsigned int index = 0;

		while(n_to_do_bits > 0)
		{
			int rngtest_loop, rc_fips140 = 0, rc_scc = 0;
			int cur_n_to_get_bits = min(pool_vector.at(index) -> get_pool_size(), n_to_do_bits);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;
			int got_n_bits, got_n_bytes;

			got_n_bytes = pool_vector.at(index) -> get_entropy_data(cur_p, cur_n_to_get_bytes, 1);
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
			if (index == pool_vector.size())
				index = 0;
		}
	}

	return n_bits_retrieved;
}

int pools::find_non_full_pool()
{
	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		if (!pool_vector.at(loop) -> is_full())
			return loop;
	}

	return -1;
}

int pools::add_bits_to_pools(unsigned char *data, int n_bytes, char ignore_rngtest_fips140, fips140 *pfips, char ignore_rngtest_scc, scc *pscc)
{
	unsigned int index = 0;
	int n_bits_added = 0;

	if ((index = find_non_full_pool()) == -1)
		index = myrand(pool_vector.size());

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
			n_bits_added += pool_vector.at(index) -> add_entropy_data(buffer);
		}

		n_bytes -= n_bytes_to_add;
		data += n_bytes_to_add;

		if (pool_vector.at(index) -> is_full())
		{
			if ((index = find_non_full_pool()) == -1)
				index = myrand(pool_vector.size());
		}
	}

	// int n_pools = get_bit_sum() / POOL_SIZE;
	// if (n_pools > max_full_threshold)
		// emit_pools(n_pools - min_full_threshold);

	// min_full_threshold must be bigger than retrieve_from_disk_threshold

	return n_bits_added;
}

int pools::get_bit_sum()
{
	int bit_count = 0;

	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		bit_count += pool_vector.at(loop) -> get_n_bits_in_pool();
	}

	return bit_count;
}

int pools::add_event(long double event, unsigned char *event_data, int n_event_data)
{
	unsigned int index;

	if ((index = find_non_full_pool()) == -1)
		index = myrand(pool_vector.size());

	return pool_vector.at(index) -> add_event(event, event_data, n_event_data);
}

bool pools::all_pools_full()
{
	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		if (!pool_vector.at(loop) -> is_full())
			return false;
	}

	return true;
}
