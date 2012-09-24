// SVN: $Id$
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
	list_wunlock();

	pthread_rwlock_destroy(&list_lck);
}

void pools::list_wlock()
{
	pthread_rwlock_wrlock(&list_lck);

	my_assert(is_w_locked == false);
	is_w_locked = true;
}

void pools::list_wunlock()
{
	my_assert(is_w_locked);
	is_w_locked = false;

	pthread_rwlock_unlock(&list_lck);
}

void pools::list_runlock()
{
	pthread_rwlock_unlock(&list_lck);
}

void pools::list_rlock()
{
	pthread_rwlock_rdlock(&list_lck);
}

void pools::store_caches(unsigned int keep_n)
{
	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

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
			if (pool_vector.at(0) -> timed_lock_object(1.0) == NULL) // will always succeed due to writelock on list
			{
				if (pool_vector.at(0) -> get_n_bits_in_pool() > 0)
					pool_vector.at(0) -> dump(fh);

				pool_vector.at(0) -> unlock_object();

				delete pool_vector.at(0);
				pool_vector.erase(pool_vector.begin() + 0);
			}
		}

		fflush(fh);

		if (flock(fileno(fh), LOCK_UN) == -1)
			error_exit("flock(LOCK_UN) for %s failed", new_cache_file.c_str());

		fclose(fh);
	}

	pthread_setcanceltype(PTHREAD_CANCEL_ENABLE, NULL);
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

		if (flock(fileno(fh), LOCK_EX) == -1)
			error_exit("flock(LOCK_EX) for %s failed", cache_list.at(0).c_str());

		while(!feof(fh))
		{
			pool *new_pool = new pool(++files_loaded, fh, bce, h, s);
			pool_vector.push_back(new_pool);

			if (new_pool -> timed_lock_object(1.0) == NULL) // will always succeed due to writelock on list
			{
				bits_loaded += new_pool -> get_n_bits_in_pool();

				new_pool -> unlock_object();
			}
		}

		if (unlink(cache_list.at(0).c_str()) == -1)
			error_exit("Failed to delete cache-file %s", cache_list.at(0).c_str());

		fflush(fh);

		if (flock(fileno(fh), LOCK_UN) == -1)
			error_exit("flock(LOCK_UN) for %s failed", cache_list.at(0).c_str());

		fclose(fh);

		cache_list.erase(cache_list.begin());
	}

	dolog(LOG_DEBUG, "%d bits loaded from %d files", bits_loaded, files_loaded);
}

void pools::flush_empty_pools()
{
	unsigned int deleted = 0;
	for(int index=pool_vector.size() - 1; index >= 0; index--)
	{
		if (pool_vector.at(index) -> timed_lock_object(1.0) == NULL) // will always succeed due to writelock on list
		{
			if (pool_vector.at(index) -> get_n_bits_in_pool() == 0)
			{
				pool_vector.at(index) -> unlock_object();

				delete pool_vector.at(index);
				pool_vector.erase(pool_vector.begin() + index);

				deleted++;
			}
			else
			{
				pool_vector.at(index) -> unlock_object();
			}
		}
	}

	if (deleted)
		dolog(LOG_DEBUG, "Deleted %d empty pool(s), new count: %d", deleted, pool_vector.size());
}

void pools::merge_pools()
{
	if (pool_vector.empty())
		return;

	int n_merged = 0;

	for(int i1=0; i1 < (int(pool_vector.size()) - 1); i1++)
	{
		if (pool_vector.at(i1) -> timed_lock_object(1.0))
			continue;

		if (pool_vector.at(i1) -> is_full())
		{
			pool_vector.at(i1) -> unlock_object();
			continue;
		}

		int i1_size = pool_vector.at(i1) -> get_n_bits_in_pool();

		for(int i2=(int(pool_vector.size()) - 1); i2 >= (i1 + 1); i2--)
		{
			if (pool_vector.at(i2) -> timed_lock_object(1.0))
				continue;

			int i2_size = pool_vector.at(i2) -> get_n_bits_in_pool();
			if (i1_size + i2_size > pool_vector.at(i1) -> get_pool_size())
			{
				pool_vector.at(i2) -> unlock_object();
				continue;
			}

			int bytes = (i2_size + 7) / 8;

			unsigned char *buffer = (unsigned char *)malloc(bytes);
			lock_mem(buffer, bytes);

			pool_vector.at(i2) -> get_entropy_data(buffer, bytes, false);

			pool_vector.at(i2) -> unlock_object();

			delete pool_vector.at(i2);
			pool_vector.erase(pool_vector.begin() + i2);

			pool_vector.at(i1) -> add_entropy_data(buffer, bytes);

			memset(buffer, 0x00, bytes);
			unlock_mem(buffer, bytes);
			free(buffer);

			n_merged++;
		}

		pool_vector.at(i1) -> unlock_object();
	}

	if (n_merged)
		dolog(LOG_INFO, "%d pool(s) merged, new count: %d", n_merged, pool_vector.size());
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

// returns a locked pool
int pools::find_non_full_pool(bool timed, double max_duration)
{
	double start_ts = get_ts();

	int n = pool_vector.size();
	for(int index=0; index<n; index++)
	{
		double working = get_ts() - start_ts;
		double cur_max_duration = max(MIN_SLEEP, (max_duration - working) / double(n - index));

		pthread_cond_t *cond = NULL;
		if (timed)
			cond = pool_vector.at(index) -> timed_lock_object(cur_max_duration);
		else
			cond = pool_vector.at(index) -> lock_object();

		if (!cond)
		{
			if (!pool_vector.at(index) -> is_almost_full())
				return index;

			pool_vector.at(index) -> unlock_object();
		}
	}

	return -1;
}

// returns a locked pool
int pools::select_pool_to_add_to(bool timed, double max_time)
{
	double start_ts = get_ts();

	list_rlock();

	int index = find_non_full_pool(timed, max_time);

	if (index == -1 || pool_vector.at(index) -> is_almost_full())
	{
		// unlock the object because it is not usable (it is full)
		// and we might go and shuffle the pools (flush/merge)
		if (index != -1)
			pool_vector.at(index) -> unlock_object();

		list_runlock();
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

		list_wunlock();
		list_rlock();

		double left = max(MIN_SLEEP, max_time - (get_ts() - start_ts));

		index = find_non_full_pool(timed, left);
		if (index == -1)
		{
			// this can happen if 1. the number of in-memory-pools limit has been reached and
			// 2. the number of on-disk-pools limit has been reached
			index = myrand(pool_vector.size());

			left = max(MIN_SLEEP, max_time - (get_ts() - start_ts));

			if (pool_vector.at(index) -> timed_lock_object(left))
				index = -1;
		}
	}

	return index;
}

int pools::get_bit_sum_unlocked(double max_duration)
{
	double start_ts = get_ts();

	int bit_count = 0;
	unsigned int n = pool_vector.size();
	for(unsigned int index=0; index<n; index++)
	{
		double time_left = max(MIN_SLEEP, ((max_duration * 0.9) - (get_ts() - start_ts)) / double(n - index));

		if (!pool_vector.at(index) -> timed_lock_object(time_left))
		{
			bit_count += pool_vector.at(index) -> get_n_bits_in_pool();

			pool_vector.at(index) -> unlock_object();
		}
	}

	return bit_count;
}

int pools::get_bits_from_pools(int n_bits_requested, unsigned char **buffer, bool allow_prng, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc, double max_duration)
{
	double start_ts = get_ts();

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
		int bits_needed_to_load = n_bits_requested - get_bit_sum_unlocked(max_duration);

		// no unlock in the break: need to have the list locked later on
		if (bits_needed_to_load <= 0)
			break;

		// a 'list_relock' would be nice
		list_runlock();
		pthread_testcancel();
		list_wlock();

		flush_empty_pools();
		merge_pools();

		// due to the un- and relock this might have changed
		// also merging pools might change this value
		bits_needed_to_load = n_bits_requested - get_bit_sum_unlocked(max_duration);
		load_caches(bits_needed_to_load);

		list_wunlock();
	}
	// at this point the list is read locked

	unsigned int n = pool_vector.size();
	int pool_block_size = pool_vector.at(0) -> get_get_size();

	int get_per_pool_n = max(pool_block_size, n_bits_requested / int(n));
	int round = 0;
	for(;n_to_do_bits > 0 && round < 2;)
	{
		for(unsigned int index=0; index<n; index++)
		{
			double now_ts = get_ts();
			// FIXME divide by number of bits left divided by available in the following pools
			double time_left = max(MIN_SLEEP, ((max_duration * 0.9) - (now_ts - start_ts)) / double(n - index));

			pthread_cond_t *cond = NULL;
			if (round > 0)
				cond = pool_vector.at(index) -> timed_lock_object(time_left);
			else
				cond = pool_vector.at(index) -> lock_object();

			if (!cond)
			{
				int cur_n_to_get_bits = (round > 0 && allow_prng) ? get_per_pool_n : n_to_do_bits;
				int cur_n_to_get_bytes = (cur_n_to_get_bits + 7) / 8;

				unsigned int got_n_bytes = pool_vector.at(index) -> get_entropy_data(cur_p, cur_n_to_get_bytes, round > 0 ? allow_prng : false);
				unsigned int got_n_bits = got_n_bytes * 8;

				if (got_n_bits > 0 && verify_quality(cur_p, got_n_bytes, ignore_rngtest_fips140, pfips, ignore_rngtest_scc, pscc))
				{
					cur_p += got_n_bytes;
					n_to_do_bits -= got_n_bits;
					n_bits_retrieved += got_n_bits;

					dolog(LOG_DEBUG, "Retrieved %d bits from pool %d", got_n_bits, index);
				}

				pool_vector.at(index) -> unlock_object();
			}
		}

		round++;
	}

	list_runlock();

	return n_bits_retrieved;
}

int pools::add_bits_to_pools(unsigned char *data, int n_bytes, bool ignore_rngtest_fips140, fips140 *pfips, bool ignore_rngtest_scc, scc *pscc, double max_duration)
{
	double start_ts = get_ts();

	int n_bits_added = 0;

	int round = 0, n_was_locked = 0;
	bool first = true;
	while(n_bytes > 0)
	{
		if (first)
		{
			list_rlock();
			first = false;
		}

		int n = pool_vector.size();

		list_runlock();
		pthread_testcancel();

		double now_ts = get_ts();
		// FIXME divide by number of bits left divided by pool sizes
		double time_left = max(MIN_SLEEP, ((max_duration * 0.9) - (now_ts - start_ts)) / double(n));

		int index = select_pool_to_add_to(round > 0, time_left); // returns a locked object
		// the list is now read-locked

		if (index == -1)
		{
			if (++n_was_locked >= n)
			{
				n_was_locked = 0;
				round++;
			}
		}
		else
		{
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

			pool_vector.at(index) -> unlock_object();
		}
	}

	list_runlock();

	return n_bits_added;
}

int pools::get_bit_sum(double max_duration)
{
	list_rlock();
	int bit_count = get_bit_sum_unlocked(max_duration);
	list_runlock();

	return bit_count;
}

int pools::add_event(long double event, unsigned char *event_data, int n_event_data, double max_time)
{
	int index = select_pool_to_add_to(true, max_time); // returns a locked object
	// the list is now read-locked and the object as well

	int rc = 0;
	if (index != -1)
	{
		rc = pool_vector.at(index) -> add_event(event, event_data, n_event_data);

		pool_vector.at(index) -> unlock_object();
	}

	list_runlock();

	return rc;
}

bool pools::all_pools_full(double max_duration)
{
	double start_ts = get_ts();

	bool rc = true;

	list_rlock();

	unsigned int n = pool_vector.size();

	if (n < max_n_mem_pools)
		rc = false;
	else
	{
		for(unsigned int loop=0; loop<n; loop++)
		{
			// FIXME move this calculation to a method
			double time_left = max(MIN_SLEEP, (max_duration - (get_ts() - start_ts)) / double(n - loop));

			if (!pool_vector.at(loop) -> timed_lock_object(time_left))
			{
				if (!pool_vector.at(loop) -> is_almost_full())
				{
					pool_vector.at(loop) -> unlock_object();

					rc = false;
					break;
				}

				pool_vector.at(loop) -> unlock_object();
			}
		}
	}

	list_runlock();

	return rc;
}
