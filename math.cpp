#include <string.h>
#include <math.h>

#include "utils.h"

int determine_number_of_bits_of_data(unsigned char *data, unsigned int n_bytes)
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
