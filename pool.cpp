#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <string.h>
#include <math.h>
#include <unistd.h>

#include "pool.h"
#include "error.h"
#include "kernel_prng_io.h"
#include "math.h"
#include "utils.h"

pool::pool()
{
	bits_in_pool = 0;

	if (kernel_rng_read_non_blocking(entropy_pool, sizeof(entropy_pool)) == -1)
		error_exit("failed reading entropy data to kernel RNG");
}

pool::pool(char *state_file)
{
	int fd = open(state_file, O_RDWR);
	if (fd == -1)
		error_exit("error opening %s", state_file);

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

int pool::get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, char prng_ok)
{
	unsigned char temp_buffer[POOL_SIZE / 8];
	unsigned char ivec[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };
	BF_KEY key;
	int n_given;
	unsigned char hash[SHA512_DIGEST_LENGTH];

	n_given = n_bytes_requested;
	if (!prng_ok)
		n_given = min(n_given, bits_in_pool / 8);
	n_given = min(n_given, SHA512_DIGEST_LENGTH);

	if (n_given > 0)
	{
		SHA512(entropy_pool, sizeof(entropy_pool), hash);
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

int pool::get_pool_size(void)
{
	return POOL_SIZE;
}
