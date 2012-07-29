#include <string.h>
#include <math.h>
#include <stdlib.h>

#include "error.h"
#include "utils.h"
#include "zlib.h"
#include "math.h"

bit_count_estimator::bit_count_estimator(bit_count_estimator_type_t type_in)
{
	type = type_in;
}

int bit_count_estimator::get_bit_count(unsigned char *data, unsigned int n_bytes)
{
	if (type == BCE_SHANNON)
		return determine_number_of_bits_of_data_shannon(data, n_bytes);
	else if (type == BCE_COMPRESSION)
		return determine_number_of_bits_of_data_compression(data, n_bytes);

	error_exit("Bit count estimator: unknown mode");

	return -1;
}

int bit_count_estimator::determine_number_of_bits_of_data_shannon(unsigned char *data, unsigned int n_bytes)
{
	int cnts[256];
	double ent = 0.0, nbytesd = double(n_bytes);
	double log2 = log(2.0);

	memset(cnts, 0x00, sizeof(cnts));

	for(unsigned int loop=0; loop<n_bytes; loop++)
	{
		cnts[data[loop]]++;
	}

	for(unsigned int loop=0; loop<256;loop++)
	{
		double prob = double(cnts[loop]) / nbytesd;

		if (prob > 0.0)
			ent += prob * (log(1.0 / prob) / log2);
	}

	ent *= nbytesd;

	if (ent < 0.0)
		ent=0.0;

	ent = min(nbytesd * 8.0, ent);

	return ent;
}

int bit_count_estimator::determine_number_of_bits_of_data_compression(unsigned char *data, unsigned int n_bytes)
{
	uLongf destLen = n_bytes * 2;
	unsigned char *dest = (unsigned char *)malloc(destLen);

	if (Z_OK != compress2(dest, &destLen, data, n_bytes, 9))
		error_exit("Failed invoking zlib");

	free(dest);

	double factor = double(destLen) / double(n_bytes);

	return int(factor * double(n_bytes) * 8.0);
}
