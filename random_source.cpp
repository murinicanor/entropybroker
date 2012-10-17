// SVN: $Revision$
#include <unistd.h>
#include <string>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "kernel_prng_io.h"
#include "kernel_prng_rw.h"
#include "random_source.h"

random_source::random_source(random_source_t rs_in) : rs(rs_in)
{
}

random_source::random_source(random_source_t rs_in, std::string state_file_in) : rs(rs_in), state_file(state_file_in)
{
	retrieve_state(state_file_in);
}

random_source::~random_source()
{
	if (state_file.length() > 0)
		dump_state(state_file);
}

void random_source::get(unsigned char *p, size_t n)
{
	if (rs == RS_CRYPTOPP)
	{
		rng.GenerateBlock(p, n);
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

bool random_source::check_empty()
{
	// FIXME /dev/[u]random, check if kernel_rng_get_entropy_count() < write_threshold

	return false;
}

void random_source::seed(unsigned char *in, size_t n, double byte_count)
{
}

void random_source::dump_state(std::string file)
{
}

void random_source::retrieve_state(std::string file)
{
}
