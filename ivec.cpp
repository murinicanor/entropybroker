// SVN: $Id$
#include <stdio.h>

#include "error.h"
#include "random_source.h"
#include "math.h"
#include "ivec.h"
#include "log.h"

ivec::ivec(int size_in, bit_count_estimator *bce_in, random_source_t rs_in) : size(size_in), bce(bce_in), rs(rs_in)
{
	init();
}

ivec::ivec(FILE *fh, int size_in, bit_count_estimator *bce_in, random_source_t rs_in) : size(size_in), bce(bce_in), rs(rs_in)
{
	init();

	unsigned char dummy = 0;
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
}

ivec::~ivec()
{
}

void ivec::dump(FILE *fh)
{
	unsigned char dummy = 0;
	if (fwrite(&dummy, 1, 1, fh) != 1)
		error_exit("ivec: error writing to stream");
}

void ivec::get(unsigned char *dest)
{
	get_random(rs, dest, size);
}

void ivec::seed(unsigned char *in, int n)
{
	double byte_count = double(bce -> get_bit_count(in, n)) / 8.0;

	seed_random(rs, in, n, byte_count);
}

bool ivec::needs_seeding() const
{
	return check_random(rs);
}
