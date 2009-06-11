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

#include "pool.h"
#include "error.h"
#include "kernel_prng_io.h"
#include "math.h"
#include "utils.h"

pool::pool()
{
	memset(&state, 0x00, sizeof(state));

	bits_in_pool = 0;

	if (kernel_rng_read_non_blocking(entropy_pool, sizeof(entropy_pool)) == -1)
		error_exit("failed reading entropy data from kernel RNG");

	if (kernel_rng_read_non_blocking(ivec, sizeof(ivec)) == -1)
		error_exit("failed reading entropy data from kernel RNG");
}

pool::pool(char *state_file)
{
	int fd = open(state_file, O_RDWR);
	if (fd == -1)
		error_exit("error opening %s", state_file);

	memset(&state, 0x00, sizeof(state));

	bits_in_pool = 0;

	if (READ(fd, (char *)entropy_pool, sizeof(entropy_pool)) != sizeof(entropy_pool))
		error_exit("file %s does not contain required %d bytes", state_file, sizeof(entropy_pool));

	close(fd);
}

pool::~pool()
{
	if (kernel_rng_write_non_blocking(entropy_pool, sizeof(entropy_pool)) == -1)
		error_exit("failed writing entropy data to kernel RNG");

	memset(entropy_pool, 0x00, sizeof(entropy_pool));
}

void pool::update_ivec(void)
{
	int loop;
	char bit = ivec[7] & 127;

	for(loop=0; loop<8; loop++)
	{
		char new_bit = ivec[loop] & 127;

		ivec[loop] <<= 1;
		ivec[loop] |= bit ? 1 : 0;

		bit = new_bit;
	}
}

int pool::add_entropy_data(unsigned char entropy_data[8])
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	BF_KEY key;
	int n_added;

	update_ivec();

	n_added = determine_number_of_bits_of_data(entropy_data, sizeof(entropy_data));

	bits_in_pool += n_added;
	if (bits_in_pool > POOL_SIZE)
		bits_in_pool = POOL_SIZE;

	BF_set_key(&key, sizeof(entropy_data), entropy_data);
	BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_ENCRYPT);
	memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));

	return n_added;
}

int pool::get_n_bits_in_pool(void)
{
	return bits_in_pool;
}

int pool::get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, char prng_ok)
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	BF_KEY key;
	int n_given;
	unsigned char hash[SHA512_DIGEST_LENGTH];
	uint32_t *hash_words = (uint32_t *)hash;

	update_ivec();

	n_given = n_bytes_requested;
	if (!prng_ok)
		n_given = min(n_given, bits_in_pool / 8);
	n_given = min(n_given, SHA512_DIGEST_LENGTH / 2); // FIXME: see folding below

	if (n_given > 0)
	{
		uint16_t w2a = hash_words[2] >> 16;
		uint16_t w2b = hash_words[2] & 0xffff;

		SHA512(entropy_pool, sizeof(entropy_pool), hash);

		// fold into 10 bytes (like linux kernel does):
		// W0^W3, W1^W4, W2[0-15] ^ W2[16-31]
		hash_words[0] ^= hash_words[3];
		hash_words[1] ^= hash_words[4];
		hash_words[2] = (w2a ^ w2b) | ((w2a ^ w2b) << 16);
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

int pool::get_pool_size(void)
{
	return POOL_SIZE;
}

int pool::is_full(void)
{
	return bits_in_pool == POOL_SIZE;
}

/* taken from random driver from linux-kernel */
int pool::add_event(double ts)
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

	return n_bits_added;
}
