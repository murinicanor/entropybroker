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
#include "math.h"
#include "pool.h"
#include "utils.h"
#include "fips140.h"
#include "scc.h"
#include "pools.h"

pools::pools(std::string cache_dir_in, unsigned int max_n_mem_pools_in, unsigned int max_n_disk_pools_in, unsigned int min_store_on_disk_n_in, bit_count_estimator *bce_in) : cache_dir(cache_dir_in), max_n_mem_pools(max_n_mem_pools_in), max_n_disk_pools(max_n_disk_pools_in), min_store_on_disk_n(min_store_on_disk_n_in), disk_limit_reached_notified(false), bce(bce_in)
{
	if (min_store_on_disk_n >= max_n_mem_pools)
		error_exit("min_store_on_disk_n must be less than max_number_of_mem_pools");
	if (min_store_on_disk_n < 1)
		error_exit("min_store_on_disk_n must be > 0");

	if (max_n_mem_pools < 3)
		error_exit("maximum number of memory pools must be at least 3");

	if (max_n_disk_pools < 1)
		error_exit("maximum number of disk pools must be at least 1");

	load_cachefiles_list();
}

pools::~pools()
{
	store_caches(0);
}

void pools::store_caches(unsigned int keep_n)
{
	if (cache_list.size() >= max_n_disk_pools)
	{
		if (!disk_limit_reached_notified)
		{
			dolog(LOG_DEBUG, "Maximum number of disk pools reached: not creating a new one");
			disk_limit_reached_notified = true;
		}
	}
	else
	{
		disk_limit_reached_notified = false;
		dolog(LOG_DEBUG, "Storing %d pools on disk (new number of files: %d)", pool_vector.size() - keep_n, cache_list.size() + 1);

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
	dolog(LOG_DEBUG, "Loading %d bits from pools", load_n_bits);

	unsigned int bits_loaded = 0;

	unsigned int files_loaded = 0;
	while(!cache_list.empty() && bits_loaded < load_n_bits)
	{
		dolog(LOG_DEBUG, "Load bits from %s", cache_list.at(0).c_str());
		FILE *fh = fopen(cache_list.at(0).c_str(), "r");
		if (!fh)
			error_exit("Failed to open cache-file %s", cache_list.at(0).c_str());

		while(!feof(fh))
		{
			pool *new_pool = new pool(++files_loaded, fh, bce);
			pool_vector.push_back(new_pool);

			bits_loaded += new_pool -> get_n_bits_in_pool();
		}

		if (unlink(cache_list.at(0).c_str()) == -1)
			error_exit("Failed to delete cache-file %s", cache_list.at(0).c_str());

		cache_list.erase(cache_list.begin());
	}
}

void pools::flush_empty_pools()
{
	unsigned int deleted = 0;
	for(unsigned int index=0; index<pool_vector.size();)
	{
		if (pool_vector.at(index) -> get_n_bits_in_pool() == 0)
		{
			delete pool_vector.at(index);
			pool_vector.erase(pool_vector.begin() + index);

			deleted++;
		}
		else
		{
			index++;
		}
	}

	if (deleted)
		dolog(LOG_DEBUG, "Deleted %d empty pools", deleted);
}

void pools::merge_pools()
{
	if (pool_vector.empty())
		return;

	int n_merged = 0;
	unsigned char buffer[POOL_SIZE / 8];
	for(unsigned int i1=0; i1<(pool_vector.size() - 1); i1++)
	{
		if (pool_vector.at(i1) -> is_full())
			continue;

		int i1_size = pool_vector.at(i1) -> get_n_bits_in_pool();

		for(unsigned int i2=(i1 + 1); i2 < pool_vector.size(); i2++)
		{
			int i2_size = pool_vector.at(i2) -> get_n_bits_in_pool();
			if (i1_size + i2_size > POOL_SIZE)
				continue;

			int bytes = (i2_size + 7) / 8;
			pool_vector.at(i2) -> get_entropy_data(buffer, bytes, false);
			pool_vector.erase(pool_vector.begin() + i2);

			pool_vector.at(i1) -> add_entropy_data(buffer, bytes);

			n_merged++;
		}
	}

	if (n_merged)
		dolog(LOG_INFO, "%d merged", n_merged);
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
	{
		flush_empty_pools();
		merge_pools();

		load_caches(bits_needed_to_load);
	}

	// search from the end as those pools will have the least number of bits
	// (unless pools from disk were retrieved, then the first pool might have less
	// bits - it will then have less bits than the pool block size)
	for(int loop=pool_vector.size() - 1; loop >= 0; loop--)
	{
		// this gets the minimum number of bits one can retrieve from a
		// pool in one request
		int pool_block_size = pool_vector.at(loop) -> get_get_size();

		while(pool_vector.at(loop) -> get_n_bits_in_pool() > pool_block_size)
		{
			int cur_n_to_get_bits = min(n_to_do_bits, pool_block_size);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

			unsigned int got_n_bytes = pool_vector.at(loop) -> get_entropy_data(cur_p, cur_n_to_get_bytes, 0);
			unsigned int got_n_bits = got_n_bytes * 8;

			for(unsigned int rngtest_loop=0; rngtest_loop<got_n_bytes; rngtest_loop++)
			{
				pfips -> add(cur_p[rngtest_loop]);
				pscc -> add(cur_p[rngtest_loop]);
			}

			bool rc_fips140 = true, rc_scc = true;
			if (!ignore_rngtest_fips140)
				rc_fips140 = pfips -> is_ok();
			if (!ignore_rngtest_scc)
				rc_scc = pfips -> is_ok();
			if (rc_fips140 == true && rc_scc == true)
			{
				cur_p += got_n_bytes;
				n_to_do_bits -= got_n_bits;
				n_bits_retrieved += got_n_bits;
			}

			// can be less due to the pool block size (more bits might
			// get returned than what was requested)
			if (n_to_do_bits <= 0)
				return n_bits_retrieved;
		}
	}

	if (allow_prng)
	{
		unsigned int index = 0;

		while(n_to_do_bits > 0)
		{
			int cur_n_to_get_bits = min(pool_vector.at(index) -> get_pool_size(), n_to_do_bits);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

			unsigned int got_n_bytes = pool_vector.at(index) -> get_entropy_data(cur_p, cur_n_to_get_bytes, 1);
			unsigned int got_n_bits = got_n_bytes * 8;

			for(unsigned int rngtest_loop=0; rngtest_loop<got_n_bytes; rngtest_loop++)
			{
				pfips -> add(cur_p[rngtest_loop]);
				pscc -> add(cur_p[rngtest_loop]);
			}

			bool rc_fips140 = true, rc_scc = true;
			if (!ignore_rngtest_fips140)
				rc_fips140 = pfips -> is_ok();
			if (!ignore_rngtest_scc)
				rc_scc = pfips -> is_ok();
			if (rc_fips140 == true && rc_scc == true)
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
		if (!pool_vector.at(loop) -> is_almost_full())
			return loop;
	}

	return -1;
}

int pools::select_pool_to_add_to()
{
	int index = find_non_full_pool();

	if (index == -1 || pool_vector.at(index) -> is_almost_full())
	{
		flush_empty_pools();
		merge_pools();

		if (pool_vector.size() >= max_n_mem_pools)
			store_caches(max(0, int(pool_vector.size()) - int(min_store_on_disk_n)));

		// see if the number of in-memory pools is reduced after the call to store_caches
		// it might have not stored any on disk if the limit on the number of files has been reached
		if (pool_vector.size() < max_n_mem_pools)
		{
			dolog(LOG_DEBUG, "Adding empty pool to queue (new number of pools: %d)", pool_vector.size() + 1);
			pool_vector.push_back(new pool(bce));
		}

		index = find_non_full_pool();
		if (index == -1)
		{
			// this can happen if 1. the number of in-memory-pools limit has been reached and
			// 2. the number of on-disk-pools limit has been reached
			index = myrand(pool_vector.size());
		}
	}

	return index;
}

int pools::add_bits_to_pools(unsigned char *data, int n_bytes, char ignore_rngtest_fips140, fips140 *pfips, char ignore_rngtest_scc, scc *pscc)
{
	int n_bits_added = 0;
	int index = -1;

	while(n_bytes > 0)
	{
		index = select_pool_to_add_to();

		int space_available = POOL_SIZE - pool_vector.at(index) -> get_n_bits_in_pool();
		// in that case we're already mixing in so we can change all data anyway
		// this only happens when all pools are full
		if (space_available <= pool_vector.at(index) -> get_get_size_in_bits())
			space_available = POOL_SIZE;

		dolog(LOG_DEBUG, "Adding %d bits to pool %d", space_available, index);
		unsigned int n_bytes_to_add = (space_available + 7) / 8;

		for(unsigned int rngtest_loop=0; rngtest_loop<n_bytes_to_add; rngtest_loop++)
		{
			pfips -> add(data[rngtest_loop]);
			pscc -> add(data[rngtest_loop]);
		}

		bool rc_fips140 = true, rc_scc = true;
		if (!ignore_rngtest_fips140)
			rc_fips140 = pfips -> is_ok();
		if (!ignore_rngtest_scc)
			rc_scc = pfips -> is_ok();
		if (rc_fips140 == true && rc_scc == true)
		{
			n_bits_added += pool_vector.at(index) -> add_entropy_data(data, n_bytes_to_add);
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
	unsigned int index = select_pool_to_add_to();

	return pool_vector.at(index) -> add_event(event, event_data, n_event_data);
}

bool pools::all_pools_full()
{
	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		if (!pool_vector.at(loop) -> is_almost_full())
			return false;
	}

	return true;
}
