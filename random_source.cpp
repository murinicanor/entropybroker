// SVN: $Revision$
#include <unistd.h>
#include <string>
#include <cryptopp/osrng.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "kernel_prng_io.h"
#include "kernel_prng_rw.h"
#include "random_source.h"

CryptoPP::AutoSeededRandomPool rng;

pthread_mutex_t lock_rand = PTHREAD_MUTEX_INITIALIZER;

void get_random(random_source_t rs, unsigned char *p, size_t n)
{
	if (rs == RS_CRYPTOPP)
	{
		pthread_check(pthread_mutex_lock(&lock_rand), "pthread_mutex_lock");
		rng.GenerateBlock(p, n);
		pthread_check(pthread_mutex_unlock(&lock_rand), "pthread_mutex_lock");
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
	// FIXME /dev/[u]random, check if kernel_rng_get_entropy_count() < write_threshold

	return false;
}

void seed_random(random_source_t rs, unsigned char *in, size_t n, double byte_count)
{
}

void dump_random_state(random_source_t rs, char *file)
{
}

void retrieve_random_state(random_source_t rs, char *file)
{
}
