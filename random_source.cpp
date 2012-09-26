#include <openssl/rand.h>

#include "error.h"
#include "kernel_prng_io.h"
#include "kernel_prng_rw.h"
#include "random_source.h"

void get_random(random_source_t rs, unsigned char *p, size_t n)
{
	if (rs == RS_OPENSSL)
	{
		if (RAND_bytes(p, n) == 0)
			error_exit("RAND_bytes failed");
	}
	else if (rs == RS_DEV_URANDOM)
	{
		if (kernel_rng_read_non_blocking(p, n) == -1)
			error_exit("kernel_rng_read_non_blocking failed");
	}
	else if (rs == RS_DEV_RANDOM)
	{
		if (kernel_rng_read_blocking(p, n) == -1)
			error_exit("kernel_rng_read_non_blocking failed");
	}
	else
	{
		error_exit("Unknown random source %s", rs);
	}
}

bool check_random_empty(random_source_t rs)
{
	if (rs == RS_OPENSSL)
		return RAND_status() == 0 ? true : false;

	// FIXME /dev/[u]random, check if kernel_rng_get_entropy_count() < write_threshold

	return false;
}

void seed_random(random_source_t rs, unsigned char *in, size_t n, double byte_count)
{
	if (rs == RS_OPENSSL)
		RAND_add(in, n, byte_count);
}

void dump_random_state(char *file)
{
	if (rs == RS_OPENSSL)
	{
		if (RAND_write_file(file) == -1)
		{
			unlink(file);

			dolog(LOG_INFO, "SSL PRNG seed file deleted: not enough entropy data");
		}
	}
}

void retrieve_random_state(char *file)
{
	if (file_exist(file))
	{
		if (irs == RS_OPENSSL)
			RAND_load_file(file, -1);

		unlink(file);
	}
}
