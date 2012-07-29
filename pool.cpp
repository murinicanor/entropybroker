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
#include <openssl/sha.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "math.h"
#include "pool.h"
#include "error.h"
#include "kernel_prng_rw.h"
#include "log.h"
#include "utils.h"

pool::pool(bit_count_estimator *bce_in) : bce(bce_in)
{
	memset(&state, 0x00, sizeof(state));

	bits_in_pool = 0;

	if (kernel_rng_read_non_blocking(entropy_pool, sizeof(entropy_pool)) == -1)
		error_exit("failed reading entropy data from kernel RNG");

	if (kernel_rng_read_non_blocking(ivec, sizeof(ivec)) == -1)
		error_exit("failed reading entropy data from kernel RNG");
}

pool::pool(int pool_nr, FILE *fh, bit_count_estimator *bce_in) : bce(bce_in)
{
	unsigned char val_buffer[4];

	if (fread(val_buffer, 1, 4, fh) <= 0)
		bits_in_pool = 0;
	else
	{
		bits_in_pool = (val_buffer[0] << 24) + (val_buffer[1] << 16) + (val_buffer[2] << 8) + val_buffer[3];

		if (fread(entropy_pool, 1, POOL_SIZE / 8, fh) != POOL_SIZE / 8)
			error_exit("Dump is corrupt (1)");

		if (fread(ivec, 1, 8, fh) != 8)
			error_exit("Dump is corrupt (2)");

		dolog(LOG_DEBUG, "Pool %d: loaded %d bits from cache", pool_nr, bits_in_pool);
	}

	memset(&state, 0x00, sizeof(state));
}

pool::~pool()
{
	if (kernel_rng_write_non_blocking(entropy_pool, sizeof(entropy_pool)) == -1)
		error_exit("failed writing entropy data to kernel RNG");

	memset(entropy_pool, 0x00, sizeof(entropy_pool));
}

void pool::dump(FILE *fh)
{
	unsigned char val_buffer[4];

	val_buffer[0] = (bits_in_pool >> 24) & 255;
	val_buffer[1] = (bits_in_pool >> 16) & 255;
	val_buffer[2] = (bits_in_pool >>  8) & 255;
	val_buffer[3] = (bits_in_pool      ) & 255;

	if (fwrite(val_buffer, 1, 4, fh) != 4)
		error_exit("Cannot write to dump (1)");

	if (fwrite(entropy_pool, 1, POOL_SIZE / 8, fh) != POOL_SIZE / 8)
		error_exit("Cannot write to dump (2)");

	if (fwrite(ivec, 1, 8, fh) != 8)
		error_exit("Cannot write to dump (3)");
}

void pool::update_ivec(void)
{
	int loop;
	char bit = ivec[7] & 128;

	for(loop=0; loop<8; loop++)
	{
		char new_bit = ivec[loop] & 128;

		ivec[loop] <<= 1;
		ivec[loop] |= bit ? 1 : 0;

		bit = new_bit;
	}
}

int pool::add_entropy_data(unsigned char *entropy_data, int n_bytes_in)
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	int n_added = bce -> get_bit_count(entropy_data, n_bytes_in);

	while(n_bytes_in > 0)
	{
		BF_KEY key;

		update_ivec();

		// when adding data to the pool, we encrypt the pool using blowfish with
		// the entropy-data as the encryption-key. blowfish allows keysizes with
		// a maximum of 448 bits which is 56 bytes
		int cur_to_add = min(n_bytes_in, 56);

		BF_set_key(&key, cur_to_add, entropy_data);
		BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_ENCRYPT);
		memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));

		entropy_data += cur_to_add;
		n_bytes_in -= cur_to_add;
	}

	bits_in_pool += n_added;
	if (bits_in_pool > POOL_SIZE)
		bits_in_pool = POOL_SIZE;

	return n_added;
}

int pool::get_n_bits_in_pool(void)
{
	return bits_in_pool;
}

int pool::get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, bool prng_ok)
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	BF_KEY key;
	// make sure the hash length is equal or less than 448 bits which is the maximum
	// blowfish key size
	int n_given, half_sha512_hash_len = SHA512_DIGEST_LENGTH / 2;;
	unsigned char hash[SHA512_DIGEST_LENGTH];

	update_ivec();

	n_given = n_bytes_requested;
	if (!prng_ok)
		n_given = min(n_given, bits_in_pool / 8);
	n_given = min(n_given, half_sha512_hash_len); // FIXME: see folding below

	if (n_given > 0)
	{
		int loop;

		SHA512(entropy_pool, sizeof(entropy_pool), hash);

		// fold into 32 bytes
		for(loop=0; loop<half_sha512_hash_len; loop++)
			hash[loop] ^= hash[loop + half_sha512_hash_len];
		memcpy(entropy_data, hash, n_given);

		bits_in_pool -= (n_given * 8);
		if (bits_in_pool < 0)
			bits_in_pool = 0;

		BF_set_key(&key, sizeof(hash), hash);
		BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_DECRYPT);
		memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));
	}

	return n_given;
}

int pool::get_get_size()
{
	return SHA512_DIGEST_LENGTH / 2;
}

int pool::get_get_size_in_bits()
{
	return get_get_size() * 8;
}

int pool::get_pool_size(void)
{
	return POOL_SIZE;
}

bool pool::is_full(void)
{
	return bits_in_pool == POOL_SIZE;
}

bool pool::is_almost_full(void)
{
	return (POOL_SIZE - bits_in_pool) < get_get_size_in_bits();
}

/* taken from random driver from linux-kernel */
int pool::add_event(double ts, unsigned char *event_data, int n_event_data)
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	BF_KEY key;
	int n_bits_added;
	double delta, delta2, delta3;

	update_ivec();

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
	if (bits_in_pool > POOL_SIZE)
		bits_in_pool = POOL_SIZE;

	BF_set_key(&key, sizeof(ts), (const unsigned char *)&ts);
	BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_ENCRYPT);
	memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));

	if (event_data)
	{
		BF_set_key(&key, n_event_data, event_data);
		BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_ENCRYPT);
		memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));
	}

	return n_bits_added;
}
