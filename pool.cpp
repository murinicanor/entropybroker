#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <string.h>
#include <math.h>

#include "pool.h"

#define min(x, y)       ((x)<(y)?(x):(y))

pool::pool()
{
	bits_in_pool = 0;
}

pool::~pool()
{
	memset(entropy_pool, 0x00, sizeof(entropy_pool));
}

int pool::determine_number_of_bits_of_data(unsigned char *data, int n_bytes)
{
	int cnts[256], loop;
	double ent=0.0;

	memset(cnts, 0x00, sizeof(cnts));

	for(loop=0; loop<n_bytes; loop++)
	{
		cnts[data[loop]]++;
	}

	for(loop=0; loop<256;loop++)
	{
		double prob = (double)cnts[loop] / (double)n_bytes;

		if (prob > 0.0)
		{
			ent += prob * (log(1.0/prob)/log(2.0));
		}
	}

	ent *= (double)n_bytes;

	if (ent < 0.0) ent=0.0;

	ent = min((double)(n_bytes*8), ent);

	return ent;
}

int pool::add_entropy_data(unsigned char entropy_data[8])
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	unsigned char ivec[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	BF_KEY key;
	int rc = -1;

	bits_in_pool += determine_number_of_bits_of_data(entropy_data, sizeof(entropy_data));
	if (bits_in_pool >= POOL_SIZE)
	{
		bits_in_pool = POOL_SIZE;
		rc = 0;
	}

	BF_set_key(&key, sizeof(entropy_data), entropy_data);
	BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_ENCRYPT);
	memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));

	return rc;
}

int pool::get_n_bits_in_pool(void)
{
	return bits_in_pool;
}

int pool::get_entropy_data(unsigned char entropy_data[8])
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	unsigned char ivec[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	BF_KEY key;
	int rc = 0;
	unsigned char hash[SHA512_DIGEST_LENGTH];

	if (bits_in_pool < 64)
		rc = -1;

	SHA512(entropy_pool, sizeof(entropy_pool), hash);
	memcpy(entropy_data, hash, sizeof(entropy_data));

	bits_in_pool -= 64;
	if (bits_in_pool < 0)
		bits_in_pool = 0;

	BF_set_key(&key, sizeof(hash), hash);
	BF_cbc_encrypt(entropy_pool, temp_buffer, (POOL_SIZE / 8), &key, ivec, BF_DECRYPT);
	memcpy(entropy_pool, temp_buffer, (POOL_SIZE / 8));

	return rc;
}
