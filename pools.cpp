#include <math.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <vector>
#include <string>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "error.h"
#include "log.h"
#include "pool.h"
#include "utils.h"
#include "fips140.h"
#include "scc.h"
#include "pools.h"

pools::pools(std::string cache_dir_in, unsigned int max_n_mem_pools_in, unsigned int max_n_disk_pools_in) : cache_dir(cache_dir_in), max_n_mem_pools(max_n_mem_pools_in), max_n_disk_pools(max_n_disk_pools_in)
{
	if (max_n_mem_pools < 3)
		error_exit("maximum number of memory pools must be at least 3");

	if (max_n_disk_pools < 2)
		error_exit("maximum number of disk pools must be at least 2");

	load_cachefiles_list();
}

pools::~pools()
{
	store_caches(0);
}

void pools::store_caches(unsigned int keep_n)
{
	if (cache_list.size() >= max_n_disk_pools)
		dolog(LOG_DEBUG, "Maximum number of disk pools reached: not creating a new one");
	else
	{
		long double now = get_ts_ns();
		char buffer[128];
		snprintf(buffer, sizeof buffer, "%Lf", now);

		std::string new_cache_file = cache_dir + "/" + std::string(buffer) + ".dat";
		FILE *fh = fopen(new_cache_file.c_str(), "wb");
		if (!fh)
			error_exit("Failed to create file %s", new_cache_file.c_str());
		cache_list.push_back(new_cache_file);

		while(pool_vector.size() > keep_n)
		{
			if (pool_vector.at(0) -> get_n_bits_in_pool() > 0)
				pool_vector.at(0) -> dump(fh);

			delete pool_vector.at(0);
			pool_vector.erase(pool_vector.begin());
		}

		fclose(fh);
	}
}

void pools::load_caches(unsigned int load_n_bits)
{
	unsigned int bits_loaded = 0;

	unsigned int files_loaded = 0;
	while(cache_list.size() > 0 && bits_loaded < load_n_bits)
	{
		dolog(LOG_DEBUG, "Load bits from %s", cache_list.at(0).c_str());
		FILE *fh = fopen(cache_list.at(0).c_str(), "r");
		if (!fh)
			error_exit("Failed to open cache-file %s", cache_list.at(0).c_str());

		while(!feof(fh))
		{
			pool *new_pool = new pool(++files_loaded, fh);
			pool_vector.push_back(new_pool);

			bits_loaded += new_pool -> get_n_bits_in_pool();
		}

		if (unlink(cache_list.at(0).c_str()) == -1)
			error_exit("Failed to delete cache-file %s", cache_list.at(0).c_str());

		cache_list.erase(cache_list.begin());
	}
}

void pools::load_cachefiles_list()
{
	DIR *dirp = opendir(cache_dir.c_str());
	if (!dirp)
		error_exit("Failed to open directory %s", cache_dir.c_str());

	struct dirent *de = NULL;
	while((de = readdir(dirp)) != NULL)
	{
		std::string file_name = cache_dir + "/" + std::string(de -> d_name);

		struct stat ss;
		if (stat(file_name.c_str(), &ss) == -1)
		{
			if (errno == EEXIST)
				dolog(LOG_WARNING, "File %s suddenly disappeared?!", file_name.c_str());

			error_exit("Error doing stat on %s", file_name.c_str());
		}

		if (ss.st_mode & S_IFDIR)
			continue;


		dolog(LOG_DEBUG, "Added %s to cache list", file_name.c_str());
		cache_list.push_back(file_name);
	}

	closedir(dirp);
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

	// load bits from disk if needed
	int bits_needed_to_load = n_bits_requested - get_bit_sum();
	if (bits_needed_to_load > 0)
		load_caches(bits_needed_to_load);

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
	int n_bits_added = 0;
	int index = find_non_full_pool();

	while(n_bytes > 0)
	{
		if (index == -1 || pool_vector.at(index) -> is_full())
		{
			if (pool_vector.size() >= max_n_mem_pools)
				store_caches(pool_vector.size() - 2); // FIXME: make this '2' configurable, see also '3'-check in constructor

			// see if the number of in-memory pools is reduced after the call to store_caches
			// it might have not stored any on disk if the limit on the number of files has been reached
			if (pool_vector.size() < max_n_mem_pools)
				pool_vector.push_back(new pool());

			index = find_non_full_pool();
			if (index == -1)
			{
				// this can happen if 1. the number of in-memory-pools limit has been reached and
				// 2. the number of on-disk-pools limit has been reached
				index = myrand(pool_vector.size());
			}
		}

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
	}

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
