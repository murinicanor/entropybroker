#include <stdio.h>
#include <openssl/rand.h>

#include "error.h"
#include "math.h"
#include "ivec.h"
#include "log.h"

ivec::ivec(bit_count_estimator *bce_in) : bce(bce_in)
{
	init();
}

ivec::ivec(FILE *fh, bit_count_estimator *bce_in) : bce(bce_in)
{
	init();
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
}

void ivec::get(unsigned char *dest)
{
	if (RAND_bytes(dest, 8) == 0)
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
