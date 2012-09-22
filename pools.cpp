#include <math.h>
#include <assert.h>
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
#include <sys/file.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "error.h"
#include "log.h"
#include "math.h"
#include "ivec.h"
#include "hasher.h"
#include "stirrer.h"
#include "pool.h"
#include "utils.h"
#include "fips140.h"
#include "scc.h"
#include "pools.h"

pools::pools(std::string cache_dir_in, unsigned int max_n_mem_pools_in, unsigned int max_n_disk_pools_in, unsigned int min_store_on_disk_n_in, bit_count_estimator *bce_in, int new_pool_size_in_bytes, hasher *hclass, stirrer *sclass) : cache_dir(cache_dir_in), max_n_mem_pools(max_n_mem_pools_in), max_n_disk_pools(max_n_disk_pools_in), min_store_on_disk_n(min_store_on_disk_n_in), disk_limit_reached_notified(false), bce(bce_in), h(hclass), s(sclass)
{
	pthread_rwlock_init(&list_lck, NULL);
	is_w_locked = false;
	is_r_locked = 0;

	new_pool_size = new_pool_size_in_bytes;

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
	list_wlock();
	store_caches(0);
	list_unlock();

	pthread_rwlock_destroy(&list_lck);
}

void pools::list_wlock()
{
	pthread_rwlock_wrlock(&list_lck);
	is_w_locked = true;
}

void pools::list_unlock()
{
	assert(is_w_locked || is_r_locked > 0);

	if (is_w_locked)
		is_w_locked = false;
	else
		is_r_locked--;

	assert(is_r_locked >= 0);

	pthread_rwlock_unlock(&list_lck);
}

void pools::list_rlock()
{
	pthread_rwlock_rdlock(&list_lck);
	assert(is_r_locked >= 0);
	is_r_locked++;
}

void pools::store_caches(unsigned int keep_n)
{
	assert(is_w_locked);

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

		std::string new_cache_file = cache_dir + "/" + std::string(buffer) + ".pool";
		FILE *fh = fopen(new_cache_file.c_str(), "wb");
		if (!fh)
			error_exit("Failed to create file %s", new_cache_file.c_str());
		cache_list.push_back(new_cache_file);

		if (flock(fileno(fh), LOCK_EX) == -1)
			error_exit("flock(LOCK_EX) for %s failed", new_cache_file.c_str());

		while(pool_vector.size() > keep_n)
		{
			if (pool_vector.at(0) -> get_n_bits_in_pool() > 0)
				pool_vector.at(0) -> dump(fh);

			delete pool_vector.at(0);
			pool_vector.erase(pool_vector.begin() + 0);
		}

		fflush(fh);

		if (flock(fileno(fh), LOCK_UN) == -1)
			error_exit("flock(LOCK_UN) for %s failed", new_cache_file.c_str());

		fclose(fh);
	}
}

void pools::load_caches(unsigned int load_n_bits)
{
	assert(is_w_locked);
	dolog(LOG_DEBUG, "Loading %d bits from pools", load_n_bits);

	unsigned int bits_loaded = 0;

	unsigned int files_loaded = 0;
	while(!cache_list.empty() && bits_loaded < load_n_bits)
	{
		dolog(LOG_DEBUG, "Load bits from %s", cache_list.at(0).c_str());
		FILE *fh = fopen(cache_list.at(0).c_str(), "r");
		if (!fh)
			error_exit("Failed to open cache-file %s", cache_list.at(0).c_str());

		if (flock(fileno(fh), LOCK_EX) == -1)
			error_exit("flock(LOCK_EX) for %s failed", cache_list.at(0).c_str());

		while(!feof(fh))
		{
			pool *new_pool = new pool(++files_loaded, fh, bce, h, s);
			pool_vector.push_back(new_pool);

			bits_loaded += new_pool -> get_n_bits_in_pool();
		}

		if (unlink(cache_list.at(0).c_str()) == -1)
			error_exit("Failed to delete cache-file %s", cache_list.at(0).c_str());

		fflush(fh);

		if (flock(fileno(fh), LOCK_UN) == -1)
			error_exit("flock(LOCK_UN) for %s failed", cache_list.at(0).c_str());

		fclose(fh);

		cache_list.erase(cache_list.begin());
	}
}

void pools::flush_empty_pools()
{
	assert(is_w_locked);
	unsigned int deleted = 0;
	for(int index=pool_vector.size() - 1; index >= 0; index--)
	{
		if (pool_vector.at(index) -> get_n_bits_in_pool() == 0)
		{
			delete pool_vector.at(index);
			pool_vector.erase(pool_vector.begin() + index);

			deleted++;
		}
	}

	if (deleted)
		dolog(LOG_DEBUG, "Deleted %d empty pools", deleted);
}

void pools::merge_pools()
{
	assert(is_w_locked);

	if (pool_vector.empty())
		return;

	int n_merged = 0;

	for(int i1=0; i1 < (int(pool_vector.size()) - 1); i1++)
	{
		if (pool_vector.at(i1) -> is_full())
			continue;

		int i1_size = pool_vector.at(i1) -> get_n_bits_in_pool();

		for(int i2=(int(pool_vector.size()) - 1); i2 >= (i1 + 1); i2--)
		{
			int i2_size = pool_vector.at(i2) -> get_n_bits_in_pool();
			if (i1_size + i2_size > pool_vector.at(i1) -> get_pool_size())
				continue;

			int bytes = (i2_size + 7) / 8;

			unsigned char *buffer = (unsigned char *)malloc(bytes);
			lock_mem(buffer, bytes);

			pool_vector.at(i2) -> get_entropy_data(buffer, bytes, false);

			delete pool_vector.at(i2);
			pool_vector.erase(pool_vector.begin() + i2);

			pool_vector.at(i1) -> add_entropy_data(buffer, bytes);

			memset(buffer, 0x00, bytes);
			unlock_mem(buffer, bytes);
			free(buffer);

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

		if (file_name.substr(file_name.size() - 5, 5) == ".pool")
		{
			dolog(LOG_DEBUG, "Added %s to cache list", file_name.c_str());
			cache_list.push_back(file_name);
		}
	}

	closedir(dirp);
}

bool pools::verify_quality(unsigned char *data, int n, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc)
{
	if (!ignore_rngtest_fips140 || !ignore_rngtest_scc)
	{
		for(int rngtest_loop=0; rngtest_loop<n; rngtest_loop++)
		{
			pfips -> add(data[rngtest_loop]);
			pscc -> add(data[rngtest_loop]);
		}
	}

	bool rc_fips140 = true, rc_scc = true;

	if (!ignore_rngtest_fips140)
		rc_fips140 = pfips -> is_ok();

	if (!ignore_rngtest_scc)
		rc_scc = pfips -> is_ok();

	return rc_fips140 == true && rc_scc == true;
}

int pools::find_non_full_pool() const
{
	assert(is_w_locked || is_r_locked > 0);

	int n = pool_vector.size();
	if (n > 0)
	{
		int offset = myrand() % n;

		for(int loop=0; loop<n; loop++)
		{
			int index = (offset + loop) % n;

			if (!pool_vector.at(index) -> is_almost_full())
				return index;
		}
	}

	return -1;
}

int pools::select_pool_to_add_to()
{
	list_rlock();

	int index = find_non_full_pool();

	if (index == -1 || pool_vector.at(index) -> is_almost_full())
	{
		list_unlock();
		list_wlock();
		// at this point (due to context switching between the unlock and the
		// wlock), there may already be a non-empty pool: that is not a problem

		flush_empty_pools();
		merge_pools();

		if (pool_vector.size() >= max_n_mem_pools)
			store_caches(max(0, int(pool_vector.size()) - int(min_store_on_disk_n)));

		// see if the number of in-memory pools is reduced after the call to store_caches
		// it might have not stored any on disk if the limit on the number of files has been reached
		if (pool_vector.size() < max_n_mem_pools)
		{
			dolog(LOG_DEBUG, "Adding empty pool to queue (new number of pools: %d)", pool_vector.size() + 1);
			pool_vector.push_back(new pool(new_pool_size, bce, h, s));
		}

		list_unlock();

		list_rlock();
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

int pools::get_bit_sum_unlocked()
{
	assert(is_w_locked || is_r_locked > 0);

	int bit_count = 0;

	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
		bit_count += pool_vector.at(loop) -> get_n_bits_in_pool();

	return bit_count;
}

int pools::get_bits_from_pools(int n_bits_requested, unsigned char **buffer, bool allow_prng, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc)
{
	int n_to_do_bytes = (n_bits_requested + 7) / 8;
	int n_to_do_bits = n_to_do_bytes * 8;
	int n_bits_retrieved = 0;

	unsigned char *cur_p = *buffer = (unsigned char *)malloc(n_to_do_bytes + 1);
	if (!cur_p)
		error_exit("transmit_bits_to_client memory allocation failure");

	lock_mem(buffer, n_to_do_bytes);

	// load bits from disk if needed
	for(;;)
	{
		list_rlock();
		int bits_needed_to_load = n_bits_requested - get_bit_sum_unlocked();

		if (bits_needed_to_load <= 0)
			break;
		list_unlock();

		list_wlock();
		flush_empty_pools();
		merge_pools();
		load_caches(bits_needed_to_load);
		list_unlock();
	}
	// at this point the list is read locked

	int n = pool_vector.size();
	int offset = myrand() % n;
	int index = offset;
	bool round_two = false;

	// n_to_do_bits can be less than 0 due to the pool block size (more bits might
	// get returned than what was requested)
	while(n_to_do_bits > 0)
	{
		// this gets the minimum number of bits one can retrieve from a
		// pool in one request
		int pool_block_size = pool_vector.at(index) -> get_get_size();

		if (pool_vector.at(index) -> get_n_bits_in_pool() > pool_block_size || (round_two && allow_prng))
		{
			int cur_n_to_get_bits = min(n_to_do_bits, pool_block_size);
			int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

			unsigned int got_n_bytes = pool_vector.at(index) -> get_entropy_data(cur_p, cur_n_to_get_bytes, 0);
			unsigned int got_n_bits = got_n_bytes * 8;

			if (verify_quality(cur_p, got_n_bytes, ignore_rngtest_fips140, pfips, ignore_rngtest_scc, pscc))
			{
				cur_p += got_n_bytes;
				n_to_do_bits -= got_n_bits;
				n_bits_retrieved += got_n_bits;
			}
		}

		index++;
		if (index == n)
			index = 0;

		if (index == offset)
		{
			round_two = true;

			if (!allow_prng)
				break;
		}
	}

	list_unlock();

	return n_bits_retrieved;
}

int pools::add_bits_to_pools(unsigned char *data, int n_bytes, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc)
{
	int n_bits_added = 0;
	int index = -1;

	bool first = true;
	while(n_bytes > 0)
	{
		if (first)
			first = false;
		else
			list_unlock();

		index = select_pool_to_add_to();
		assert(!is_w_locked);
		// the list is now read-locked

		int space_available = pool_vector.at(index) -> get_pool_size() - pool_vector.at(index) -> get_n_bits_in_pool();
		// in that case we're already mixing in so we can change all data anyway
		// this only happens when all pools are full
		if (space_available <= pool_vector.at(index) -> get_get_size_in_bits())
			space_available = pool_vector.at(index) -> get_pool_size();

		unsigned int n_bytes_to_add = min(n_bytes, (space_available + 7) / 8);
		dolog(LOG_DEBUG, "Adding %d bits to pool %d", n_bytes_to_add * 8, index);

		if (verify_quality(data, n_bytes_to_add, ignore_rngtest_fips140, pfips, ignore_rngtest_scc, pscc))
			n_bits_added += pool_vector.at(index) -> add_entropy_data(data, n_bytes_to_add);

		n_bytes -= n_bytes_to_add;
		data += n_bytes_to_add;
	}

	list_unlock();

	return n_bits_added;
}

int pools::get_bit_sum()
{
	list_rlock();
	int bit_count = get_bit_sum_unlocked();
	list_unlock();

	return bit_count;
}

int pools::add_event(long double event, unsigned char *event_data, int n_event_data)
{
	unsigned int index = select_pool_to_add_to();
	assert(!is_w_locked);
	// the list is now read-locked

	int rc = pool_vector.at(index) -> add_event(event, event_data, n_event_data);

	list_unlock();

	return rc;
}

bool pools::all_pools_full()
{
	bool rc = true;

	list_rlock();

	for(unsigned int loop=0; loop<pool_vector.size(); loop++)
	{
		if (!pool_vector.at(loop) -> is_almost_full())
		{
			rc = false;
			break;
		}
	}

	list_unlock();

	return rc;
}
