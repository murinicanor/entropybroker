#include <unistd.h>
#include <vector>
#include <string>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "kernel_prng_io.h"
#include "kernel_prng_rw.h"
#include "random_source.h"

random_source::random_source(const random_source_t rs_in) : rs(rs_in), notified_errors(false)
{
	rng = new CryptoPP::AutoSeededRandomPool();
}

random_source::random_source(const random_source_t rs_in, const std::string & state_file_in) : rs(rs_in), state_file(state_file_in), notified_errors(false)
{
	retrieve_state(state_file_in);

	rng = new CryptoPP::AutoSeededRandomPool();
}

random_source::~random_source()
{
	if (state_file.length() > 0)
		dump_state(state_file);

	delete rng;
}

void random_source::get(unsigned char *const p, const size_t n)
{
	if (rs == RS_CRYPTOPP)
	{
		// this construction is implemented this as crypto++ 5.6.1 does not handle
		// EAGAIN errors correctly when reading from /dev/urandom
		int attempt = 0;

		for(;;)
		{
			try
			{
				rng -> GenerateBlock(p, n);

				break;
			}
			catch(CryptoPP::OS_RNG_Err ore)
			{
				if (!notified_errors)
				{
					notified_errors = true;

					dolog(LOG_WARNING, "crypto++ threw an error in the OS RNG: %s", ore.what());
				}

				if (++attempt > 16)
					error_exit("crypto++ CryptoPP::AutoSeededRandomPool() failed %d times, aborting", attempt);

				delete rng;
				rng = new CryptoPP::AutoSeededRandomPool();
			}
		}
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

bool random_source::check_empty() const
{
	// FIXME /dev/[u]random, check if kernel_rng_get_entropy_count() < write_threshold

	return false;
}

void random_source::seed(const unsigned char *const in, const size_t n, const double byte_count)
{
}

void random_source::dump_state(const std::string & file)
{
}

void random_source::retrieve_state(const std::string & file)
{
}
