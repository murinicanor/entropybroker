// SVN: $Revision$
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string>
#include <sys/mman.h>
#include <arpa/inet.h>

#include "math.h"
#include "random_source.h"
#include "hasher.h"
#include "hasher_type.h"
#include "stirrer.h"
#include "stirrer_type.h"
#include "pool_crypto.h"
#include "pool.h"
#include "error.h"
#include "kernel_prng_rw.h"
#include "log.h"
#include "utils.h"

pool::pool(int new_pool_size_bytes, bit_count_estimator *bce_in, pool_crypto *pc) : bce(bce_in)
{
	pthread_check(pthread_mutex_init(&lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_cond_init(&cond, NULL), "pthread_cond_init");

	memset(&state, 0x00, sizeof state);

	pool_size_bytes = new_pool_size_bytes;

	entropy_pool = reinterpret_cast<unsigned char *>(malloc_locked(pool_size_bytes));

	bits_in_pool = 0;

	pc -> get_random_source() -> get(entropy_pool, pool_size_bytes);
}

pool::pool(int pool_nr, FILE *fh, bit_count_estimator *bce_in, pool_crypto *pc) : bce(bce_in)
{
	pthread_check(pthread_mutex_init(&lck, &global_mutex_attr), "pthread_mutex_init");
	pthread_check(pthread_cond_init(&cond, NULL), "pthread_cond_init");

	unsigned char val_buffer[8];

	if (fread(val_buffer, 1, 8, fh) <= 0)
	{
		// FIXME throw an exception instead to prevent a 0-bits pool?
		pool_size_bytes = DEFAULT_POOL_SIZE_BITS / 8;
		bits_in_pool = 0;

		entropy_pool = reinterpret_cast<unsigned char *>(malloc_locked(pool_size_bytes));

		pc -> get_random_source() -> get(entropy_pool, pool_size_bytes);
	}
	else
	{
		bits_in_pool = (val_buffer[0] << 24) + (val_buffer[1] << 16) + (val_buffer[2] << 8) + val_buffer[3];
		if (bits_in_pool < 0 || bits_in_pool >= 4194304) // more than 4MB is ridiculous
			error_exit("Corrupt dump? bits in pool is strange! %d", bits_in_pool);

		pool_size_bytes = (val_buffer[4] << 24) + (val_buffer[5] << 16) + (val_buffer[6] << 8) + val_buffer[7];
		if (pool_size_bytes < 0 || pool_size_bytes >= 4194304) // more than 4MB is ridiculous
			error_exit("Corrupt dump? pool size is strange! %d", pool_size_bytes);

		entropy_pool = reinterpret_cast<unsigned char *>(malloc_locked(pool_size_bytes));

		int rc = -1;
		if ((rc = fread(entropy_pool, 1, pool_size_bytes, fh)) != pool_size_bytes)
			error_exit("Dump is corrupt: are you using disk-pools from an entropybroker version older than v1.1? (expected %d, got %d)", pool_size_bytes, rc);

		dolog(LOG_DEBUG, "Pool %d: loaded %d bits from cache", pool_nr, bits_in_pool);
	}

	memset(&state, 0x00, sizeof state);
}

pool::~pool()
{
	free_locked(entropy_pool, pool_size_bytes);

	pthread_check(pthread_mutex_destroy(&lck), "pthread_mutex_destroy");
	pthread_check(pthread_cond_destroy(&cond), "pthread_cond_destroy");
}

pthread_cond_t * pool::lock_object()
{
	int rc = -1;
	if ((rc = pthread_mutex_trylock(&lck)))
	{
		if (rc == EBUSY)
			return &cond;

		errno = rc;
		error_exit("pthread_mutex_trylock failed");
	}

	return NULL;
}

pthread_cond_t * pool::timed_lock_object(double max_time)
{
	my_assert(max_time > 0.0);
	struct timespec abs_time;

	while(max_time > 0.0)
	{
		pthread_testcancel();

		clock_gettime(CLOCK_REALTIME, &abs_time);

		double cur_time = mymin(max_time, 1.0);
		abs_time.tv_sec += cur_time;
		abs_time.tv_nsec += (cur_time - floor(cur_time)) * 1000000000L;

		if (abs_time.tv_nsec >= 1000000000L)
		{
			abs_time.tv_sec++;
			abs_time.tv_nsec -= 1000000000L;
		}

		int rc = -1;
		rc = pthread_mutex_timedlock(&lck, &abs_time);
		if (rc == 0)
			return NULL;

		if (rc != ETIMEDOUT)
		{
			errno = rc;
			error_exit("pthread_mutex_timedlock failed");
		}

		max_time -= cur_time;
	}

	return &cond;
}

void pool::unlock_object()
{
	my_mutex_unlock(&lck);

	pthread_check(pthread_cond_signal(&cond), "pthread_cond_signal");
}

void pool::dump(FILE *fh)
{
	if (bits_in_pool > 0)
	{
		unsigned char val_buffer[8];

		val_buffer[0] = (bits_in_pool >> 24) & 255;
		val_buffer[1] = (bits_in_pool >> 16) & 255;
		val_buffer[2] = (bits_in_pool >>  8) & 255;
		val_buffer[3] = (bits_in_pool      ) & 255;
		val_buffer[4] = (pool_size_bytes >> 24) & 255;
		val_buffer[5] = (pool_size_bytes >> 16) & 255;
		val_buffer[6] = (pool_size_bytes >>  8) & 255;
		val_buffer[7] = (pool_size_bytes      ) & 255;

		if (fwrite(val_buffer, 1, 8, fh) != 8)
			error_exit("Cannot write to dump (1)");

		if (fwrite(entropy_pool, 1, pool_size_bytes, fh) != (size_t)pool_size_bytes)
			error_exit("Cannot write to dump (2)");
	}
}

int pool::add_entropy_data(unsigned char *entropy_data, int n_bytes_in, pool_crypto *pc, int is_n_bits)
{
	my_assert(n_bytes_in > 0);

	// this implementation is described in RFC 4086 (June 2005) chapter 6.2.1, second paragraph

	// NOTE (or FIXME if you like): not entirely sure if it is good enough to use a
	// cryptographical strong PRNG to set the ivec - could use "real"
	// entropy values for that instead

	unsigned char *temp_buffer = reinterpret_cast<unsigned char *>(malloc_locked(pool_size_bytes));

	int n_added = is_n_bits;
	if (n_added == -1)
		n_added = bce -> get_bit_count(entropy_data, n_bytes_in);

	unsigned char *ivec = alloc_ivec(pc);

	while(n_bytes_in > 0)
	{
		// when adding data to the pool, we encrypt the pool using blowfish with
		// the entropy-data as the encryption-key. blowfish allows keysizes with
		// a maximum of 448 bits which is 56 bytes
		int cur_to_add = mymin(n_bytes_in, pc -> get_stirrer() -> get_stir_size());

		pc -> get_stirrer() -> do_stir(ivec, entropy_pool, pool_size_bytes, entropy_data, cur_to_add, temp_buffer, true);

		entropy_data += cur_to_add;
		n_bytes_in -= cur_to_add;
	}

	bits_in_pool += n_added;
	if (bits_in_pool > (pool_size_bytes * 8))
		bits_in_pool = (pool_size_bytes * 8);

	free_locked(temp_buffer, pool_size_bytes);

	free_ivec(pc, ivec);

	return n_added;
}

int pool::get_n_bits_in_pool() const
{
	return bits_in_pool;
}

unsigned char *pool::alloc_ivec(pool_crypto *pc)
{
	int ivec_size = pc -> get_stirrer() -> get_ivec_size();

	unsigned char *ivec = reinterpret_cast<unsigned char *>(malloc_locked(ivec_size));

	pc -> get_random_source() -> get(ivec, ivec_size);

	return ivec;
}

void pool::free_ivec(pool_crypto *pc, unsigned char *ivec)
{
	int ivec_size = pc -> get_stirrer() -> get_ivec_size();

	free_locked(ivec, ivec_size);
}

int pool::get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, bool prng_ok, pool_crypto *pc)
{
	my_assert(n_bytes_requested > 0);

	unsigned char *temp_buffer = reinterpret_cast<unsigned char *>(malloc_locked(pool_size_bytes));

	// make sure the hash length is equal or less than 448 bits which is the maximum
	// blowfish key size
	int hash_len = pc -> get_hasher() -> get_hash_size();
	int n_given, half_hash_len = hash_len / 2;;

	unsigned char *hash = reinterpret_cast<unsigned char *>(malloc_locked(hash_len));

	unsigned char *ivec = alloc_ivec(pc);

	n_given = n_bytes_requested;
	if (!prng_ok)
		n_given = mymin(n_given, bits_in_pool / 8);
	n_given = mymin(n_given, half_hash_len);

	if (n_given > 0)
	{
		int loop;

		pc -> get_hasher() -> do_hash(entropy_pool, pool_size_bytes, hash);

		bits_in_pool -= (n_given * 8);
		if (bits_in_pool < 0)
			bits_in_pool = 0;

		// if the hash is bigger than what we can stir in: fold it
		unsigned char *dummy_hash_p = hash;
		int stir_size = pc -> get_stirrer() -> get_stir_size(), index = 0;
		while(index < hash_len)
		{
			int cur_hash_n = mymin(hash_len - index, stir_size);

			pc -> get_stirrer() -> do_stir(ivec, entropy_pool, pool_size_bytes, dummy_hash_p, cur_hash_n, temp_buffer, false);

			dummy_hash_p += cur_hash_n;
			index += cur_hash_n;
		}

		// fold into half
		for(loop=0; loop<half_hash_len; loop++)
			hash[loop] ^= hash[loop + half_hash_len];
		memcpy(entropy_data, hash, n_given);
	}

	free_locked(temp_buffer, pool_size_bytes);

	free_locked(hash, hash_len);

	free_ivec(pc, ivec);

	return n_given;
}

int pool::get_get_size(pool_crypto *pc) const
{
	return pc -> get_hasher() -> get_hash_size() / 2;
}

int pool::get_get_size_in_bits(pool_crypto *pc) const
{
	return get_get_size(pc) * 8;
}

int pool::get_pool_size() const
{
	return pool_size_bytes * 8;
}

int pool::get_pool_size_bytes() const
{
	return pool_size_bytes;
}

bool pool::is_full() const
{
	return bits_in_pool == (pool_size_bytes * 8);
}

bool pool::is_almost_full(pool_crypto *pc) const
{
	return ((pool_size_bytes * 8) - bits_in_pool) < get_get_size_in_bits(pc);
}

/* taken from random driver from linux-kernel */
int pool::add_event(double ts, unsigned char *event_data, int n_event_data, pool_crypto *pc)
{
	unsigned char *temp_buffer = reinterpret_cast<unsigned char *>(malloc_locked(pool_size_bytes));

	int n_bits_added;
	double delta, delta2, delta3;

	delta = ts - state.last_time;
	state.last_time = ts;

	delta2 = delta - state.last_delta;
	state.last_delta = delta;

	delta3 = delta2 - state.last_delta2;
	state.last_delta2 = delta2;

	if (delta < 0)
		delta = -delta;
	if (delta2 < 0)
		delta2 = -delta2;
	if (delta3 < 0)
		delta3 = -delta3;
	if (delta > delta2)
		delta = delta2;
	if (delta > delta3)
		delta = delta3;

	if (delta == 0)
		n_bits_added = 0;
	else
		n_bits_added = mymax(0, mymin(MAX_EVENT_BITS, log(delta) / log(2.0)));

	bits_in_pool += n_bits_added;
	if (bits_in_pool > (pool_size_bytes * 8))
		bits_in_pool = (pool_size_bytes * 8);

	unsigned char *ivec = alloc_ivec(pc);

	pc -> get_stirrer() -> do_stir(ivec, entropy_pool, pool_size_bytes, (unsigned char *)&ts, sizeof ts, temp_buffer, true);

	while(n_event_data > 0)
	{
		int cur_n_event_data = mymin(n_event_data, pc -> get_stirrer() -> get_stir_size());

		pc -> get_stirrer() -> do_stir(ivec, entropy_pool, pool_size_bytes, event_data, cur_n_event_data, temp_buffer, true);

		event_data += cur_n_event_data;
		n_event_data -= cur_n_event_data;
	}

	free_locked(temp_buffer, pool_size_bytes);

	free_ivec(pc, ivec);

	return n_bits_added;
}

unsigned char * pool::expose_contents()
{
	bits_in_pool = 0;

	return entropy_pool;
}
