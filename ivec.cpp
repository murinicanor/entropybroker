#include <stdio.h>
#include <openssl/rand.h>

#include "error.h"
#include "math.h"
#include "ivec.h"
#include "log.h"

ivec::ivec(int size_in, bit_count_estimator *bce_in) : size(size_in), bce(bce_in)
{
	init();
}

ivec::ivec(FILE *fh, int size_in, bit_count_estimator *bce_in) : size(size_in), bce(bce_in)
{
	init();

	unsigned char dummy;
	if (fread(&dummy, 1, 1, fh) != 1)
		error_exit("ivec initializer: error reading stream");

	if (dummy)
	{
		dolog(LOG_WARNING, "Ignoring ivec data in disk-pool!");

		if (fseek(fh, dummy, SEEK_CUR) == -1)
			error_exit("ivec initializer: error seeking in file");
	}
}

void ivec::init()
{
	if (RAND_status() == 0)
		error_exit("RAND_status: prng not seeded enough");
}

ivec::~ivec()
{
}

void ivec::dump(FILE *fh)
{
	unsigned char dummy;
	if (fwrite(&dummy, 1, 1, fh) != 1)
		error_exit("ivec: error writing to stream");
}

void ivec::get(unsigned char *dest)
{
	if (RAND_bytes(dest, size) == 0)
		error_exit("RAND_bytes failed");
}

void ivec::seed(unsigned char *in, int n)
{
	double byte_count = double(bce -> get_bit_count(in, n)) / 8.0;

	RAND_add(in, n, byte_count);
}

bool ivec::needs_seeding()
{
	return false; // openssl rand takes care of that by itself
}
