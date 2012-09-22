/*
  GPL 2 applies to entropybroker.

  In addition, as a special exception, the copyright holders give
  permission to link the code of portions of this program with the
  OpenSSL library under certain conditions as described in each
  individual source file, and distribute linked combinations
  including the two.
  You must obey the GNU General Public License in all respects
  for all of the code used other than OpenSSL.  If you modify
  file(s) with this exception, you may extend this exception to your
  version of the file(s), but you are not obligated to do so.  If you
  do not wish to do so, delete this exception statement from your
  version.  If you delete this exception statement from all source
  files in the program, then also delete it here.
*/
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/blowfish.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <string>
#include <sys/mman.h>
#include <arpa/inet.h>
#include <openssl/rand.h>

#include "math.h"
#include "ivec.h"
#include "hasher.h"
#include "stirrer.h"
#include "pool.h"
#include "error.h"
#include "kernel_prng_rw.h"
#include "log.h"
#include "utils.h"

pool::pool(int new_pool_size_bytes, bit_count_estimator *bce_in, hasher *hclass, stirrer *sclass) : bce(bce_in), h(hclass), s(sclass)
{
	pthread_mutex_init(&lck, NULL);
	is_locked = false;
is_locked = true; // FIXME
	pthread_cond_init(&cond, NULL);

	memset(&state, 0x00, sizeof(state));

	pool_size_bytes = new_pool_size_bytes;
	entropy_pool = (unsigned char *)malloc(pool_size_bytes);
	lock_mem(entropy_pool, pool_size_bytes);

	bits_in_pool = 0;

	// FIXME 'paranoid' boolean that enables /dev/(u)random?
	if (RAND_bytes(entropy_pool, pool_size_bytes) == 0)
		error_exit("RAND_bytes failed");

	iv = new ivec(s -> get_ivec_size(), bce);
}

pool::pool(int pool_nr, FILE *fh, bit_count_estimator *bce_in, hasher *hclass, stirrer *sclass) : bce(bce_in), h(hclass), s(sclass)
{
	pthread_mutex_init(&lck, NULL);
	is_locked = false;
	pthread_cond_init(&cond, NULL);
is_locked = true; // FIXME

	unsigned char val_buffer[8];

	if (fread(val_buffer, 1, 8, fh) <= 0)
	{
		// FIXME throw an exception instead to prevent a 0-bits pool?
		pool_size_bytes = DEFAULT_POOL_SIZE_BITS / 8;
		entropy_pool = (unsigned char *)malloc(pool_size_bytes);
		bits_in_pool = 0;

		lock_mem(entropy_pool, pool_size_bytes);

		// FIXME 'paranoid' boolean that enables /dev/(u)random?
		if (RAND_bytes(entropy_pool, pool_size_bytes) == 0)
			error_exit("RAND_bytes failed");

		iv = new ivec(s -> get_ivec_size(), bce);
	}
	else
	{
		bits_in_pool = (val_buffer[0] << 24) + (val_buffer[1] << 16) + (val_buffer[2] << 8) + val_buffer[3];
		pool_size_bytes = (val_buffer[4] << 24) + (val_buffer[5] << 16) + (val_buffer[6] << 8) + val_buffer[7];

		entropy_pool = (unsigned char *)malloc(pool_size_bytes);
		lock_mem(entropy_pool, pool_size_bytes);

		if (fread(entropy_pool, 1, pool_size_bytes, fh) != (size_t)pool_size_bytes)
			error_exit("Dump is corrupt (using disk-pools from an entropybroker version older than v1.1?)");

		iv = new ivec(fh, s -> get_ivec_size(), bce);

		dolog(LOG_DEBUG, "Pool %d: loaded %d bits from cache", pool_nr, bits_in_pool);
	}

	memset(&state, 0x00, sizeof(state));
}

pool::~pool()
{
	memset(entropy_pool, 0x00, pool_size_bytes);
	unlock_mem(entropy_pool, pool_size_bytes);
	free(entropy_pool);

	delete iv;

	pthread_mutex_destroy(&lck);
	pthread_cond_destroy(&cond);
}

pthread_cond_t * pool::lock_object()
{
	if (pthread_mutex_trylock(&lck))
	{
		if (errno == EBUSY)
			return &cond;

		error_exit("pthread_mutex_trylock failed");
	}

	is_locked = true;

	return NULL;
}

void pool::unlock_object()
{
	is_locked = true;

	pthread_mutex_unlock(&lck);

	pthread_cond_signal(&cond);
}

void pool::dump(FILE *fh)
{
	assert(is_locked);

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

		iv -> dump(fh);
	}
}

int pool::add_entropy_data(unsigned char *entropy_data, int n_bytes_in)
{
	assert(is_locked);

	int ivec_size = s -> get_ivec_size();
	unsigned char *cur_ivec = (unsigned char *)malloc(ivec_size);
	lock_mem(cur_ivec, ivec_size);

	if (is_full() && n_bytes_in >= (24 + ivec_size) && iv -> needs_seeding())
	{
		iv -> seed(entropy_data, ivec_size);

		entropy_data += ivec_size;
		n_bytes_in -= ivec_size;
	}

	// this implementation is described in RFC 4086 (June 2005) chapter 6.2.1, second paragraph

	// NOTE (or FIXME if you like): not entirely sure if it is good enough to use a
	// cryptographical strong PRNG (the one from openssl) to set the ivec - could use "real"
	// entropy values for that instead

	unsigned char *temp_buffer = (unsigned char *)malloc(pool_size_bytes);
	lock_mem(temp_buffer, pool_size_bytes);

	int n_added = bce -> get_bit_count(entropy_data, n_bytes_in);

	while(n_bytes_in > 0)
	{
		iv -> get(cur_ivec);

		// when adding data to the pool, we encrypt the pool using blowfish with
		// the entropy-data as the encryption-key. blowfish allows keysizes with
		// a maximum of 448 bits which is 56 bytes
		int cur_to_add = min(n_bytes_in, s -> get_stir_size());

		s -> do_stir(cur_ivec, entropy_pool, pool_size_bytes, entropy_data, cur_to_add, temp_buffer, true);

		entropy_data += cur_to_add;
		n_bytes_in -= cur_to_add;
	}

	bits_in_pool += n_added;
	if (bits_in_pool > (pool_size_bytes * 8))
		bits_in_pool = (pool_size_bytes * 8);

	memset(temp_buffer, 0x00, pool_size_bytes);
	unlock_mem(temp_buffer, pool_size_bytes);
	free(temp_buffer);

	memset(cur_ivec, 0x00, ivec_size);
	unlock_mem(cur_ivec, ivec_size);
	free(cur_ivec);

	return n_added;
}

int pool::get_n_bits_in_pool() const
{
	assert(is_locked);

	return bits_in_pool;
}

int pool::get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, bool prng_ok)
{
	assert(is_locked);

	unsigned char *temp_buffer = (unsigned char *)malloc(pool_size_bytes);
	lock_mem(temp_buffer, pool_size_bytes);

	// make sure the hash length is equal or less than 448 bits which is the maximum
	// blowfish key size
	int hash_len = h -> get_hash_size();
	int n_given, half_hash_len = hash_len / 2;;
	unsigned char *hash = (unsigned char *)malloc(h -> get_hash_size());
	lock_mem(hash, hash_len);

	unsigned char cur_ivec[8];
	iv -> get(cur_ivec);

	n_given = n_bytes_requested;
	if (!prng_ok)
		n_given = min(n_given, bits_in_pool / 8);
	n_given = min(n_given, half_hash_len);

	if (n_given > 0)
	{
		int loop;

		h -> do_hash(entropy_pool, pool_size_bytes, hash);

		bits_in_pool -= (n_given * 8);
		if (bits_in_pool < 0)
			bits_in_pool = 0;

		// if the hash is bigger than what we can stir in: fold it
		unsigned char *dummy_hash_p = hash;
		int stir_size = s -> get_stir_size(), index = 0;
		while(index < hash_len)
		{
			int cur_hash_n = min(hash_len - index, stir_size);

			s -> do_stir(cur_ivec, entropy_pool, pool_size_bytes, dummy_hash_p, cur_hash_n, temp_buffer, false);

			dummy_hash_p += cur_hash_n;
			index += cur_hash_n;
		}

		// fold into half
		for(loop=0; loop<half_hash_len; loop++)
			hash[loop] ^= hash[loop + half_hash_len];
		memcpy(entropy_data, hash, n_given);
	}

	memset(temp_buffer, 0x00, pool_size_bytes);
	unlock_mem(temp_buffer, pool_size_bytes);
	free(temp_buffer);

	memset(hash, 0x00, hash_len);
	unlock_mem(hash, hash_len);
	free(hash);

	return n_given;
}

int pool::get_get_size() const
{
	return h -> get_hash_size() / 2;
}

int pool::get_get_size_in_bits() const
{
	return get_get_size() * 8;
}

int pool::get_pool_size() const
{
	return pool_size_bytes * 8;
}

bool pool::is_full() const
{
	assert(is_locked);

	return bits_in_pool == (pool_size_bytes * 8);
}

bool pool::is_almost_full() const
{
	assert(is_locked);

	return ((pool_size_bytes * 8) - bits_in_pool) < get_get_size_in_bits();
}

/* taken from random driver from linux-kernel */
int pool::add_event(double ts, unsigned char *event_data, int n_event_data)
{
	assert(is_locked);

	unsigned char *temp_buffer = (unsigned char *)malloc(pool_size_bytes);
	lock_mem(temp_buffer, pool_size_bytes);

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
		n_bits_added = max(0, min(MAX_EVENT_BITS, log(delta) / log(2.0)));

	bits_in_pool += n_bits_added;
	if (bits_in_pool > (pool_size_bytes * 8))
		bits_in_pool = (pool_size_bytes * 8);

	unsigned char cur_ivec[8];
	iv -> get(cur_ivec);

	s -> do_stir(cur_ivec, entropy_pool, pool_size_bytes, (unsigned char *)&ts, sizeof ts, temp_buffer, true);

	while(n_event_data > 0)
	{
		int cur_n_event_data = min(n_event_data, s -> get_stir_size());

		iv -> get(cur_ivec);

		s -> do_stir(cur_ivec, entropy_pool, pool_size_bytes, event_data, cur_n_event_data, temp_buffer, true);

		event_data += cur_n_event_data;
		n_event_data -= cur_n_event_data;
	}

	memset(temp_buffer, 0x00, pool_size_bytes);
	unlock_mem(temp_buffer, pool_size_bytes);
	free(temp_buffer);

	return n_bits_added;
}
