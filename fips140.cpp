/* This RNG-tester was written by F.J.J. van Heusden (folkert@vanheusden.com).
 * It was implemented according to the FIPS1401-documentation which can be
 * found at http://csrc.nist.gov/publications/fips/index.html
 * The tests are implemented so one can do the test continuously. Beware,
 * though, that the tester will ALWAYS return 'not good' when there's not
 * data! (20.000 bits) I think there's no need to always also do the long-test.
 * I think it's only needed every 20.000-34=19966 bits (34=minimum for the
 * long-run test) which is about 2495,75 bytes (round down to be conservative:
 * 2495 bytes).
 *
 * usage:
 * 	before using this thing, do fips140_init().
 *	it has no parameters and won't return anything at all
 *
 *	fips140_short(): no parameters, returns 0 if not-so-random data, 1 if
 *	the data seems to be random
 *	fips140_long(): see fips140_short(). Note: it also invokes the short-
 * 	test
 *	fips140(): calls fips140_short(), and if enough new bits were added
 *	since the last _long()-test, it also calls the long one.
 *	fips140_add(): adds 8 bits (1 byte) of data to internal bit-buffer
 *
 * Note: when an error occurs ( -> error = the data is not so random as one
 *      would expect), it'll take up to 20k bits before the tester says "ok"
 *      again. That is not a bug, it's expected behaviour.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>

#include "error.h"
#include "log.h"
#include "fips140.h"

/* array with numberofbitssetto1 */
unsigned char fips140::fips140_bit1cnt[256];

void fips140::init()
{
	/* generate table with number of bits-set-to-1 for each number */
	memset(fips140_bit1cnt, 0x00, sizeof fips140_bit1cnt);

	for(int loop=0; loop<256; loop++)
	{
		for(int bit=1; bit<256; bit<<=1)
		{
			if (loop & bit)
				fips140_bit1cnt[loop]++;
		}
	}
}

fips140::fips140() : user(NULL)
{
	memset(fips140_rval, 0x00, sizeof fips140_rval);
	memset(fips140_pokerbuf, 0x00, sizeof fips140_pokerbuf);

	fips140_p = fips140_nbits = fips140_nnewbits = fips140_n1 = 0;

	stats_t.monobit = stats_t.poker = stats_t.longrun = stats_t.runs = 0;

	fips_version = 2;
}

fips140::~fips140()
{
	free(user);
}

void fips140::set_user(const char *puser)
{
	free(user);

	user = strdup(puser);
	if (!user)
		error_exit("memory allocation error");

	dolog(LOG_DEBUG, "registered fips140-user %s", user);
}

void fips140::set_fips_version(int version)
{
	if (version != 1 && version != 2)
		error_exit("fips version should be 1 or 2, not %d", version);

	fips_version = version;
}

void fips140::add(unsigned char newval)
{
	unsigned char old = fips140_rval[fips140_p];	/* get old value */

	fips140_rval[fips140_p] = newval;		/* remember new value */
	fips140_p++;				/* go to next */
	if (fips140_p == (20000/8)) fips140_p=0;	/* ringbuffer */

	/* keep track of number of bits in ringbuffer */
	if (fips140_nbits == 20000)
	{
		/* buffer full, forget old stuff */
		fips140_n1 -= fips140_bit1cnt[old];	/* monobit test */
		fips140_pokerbuf[old & 15]--;	/* poker test */
		fips140_pokerbuf[old >> 4]--;
	}
	else	/* another 8 bits added */
	{
		fips140_nbits += 8;
	}

	/* keep track of # new bits since last longtest */
	if (fips140_nnewbits < 20000) /* prevent overflowwraps */
	{
		fips140_nnewbits += 8;
	}

	/* there must be about 50% of 1's in the bitstream
	 * (monobit test)
	 */
	fips140_n1 += fips140_bit1cnt[newval];		/* keep track of n1-counts */

	/* poker test */
	fips140_pokerbuf[newval & 15]++;	/* do the 2 nibbles */
	fips140_pokerbuf[newval >> 4]++;
}

bool fips140::fips140_shorttest()
{
	int loop;
	int total=0;
	double X;

	/* we can only say anything on this data when there had been
	 * enough data to evaluate
	 */
	if (fips140_nbits != 20000)
	{
		return true;
	}

	/* monobit test */
	if ((fips_version == 2 && (fips140_n1<=9725 || fips140_n1 >= 10275)) ||	/* passwd if 9725 < n1 < 10275 */
	    (fips_version == 1 && (fips140_n1<=9654 || fips140_n1 >= 10346)))
	{
		dolog(LOG_CRIT, "fips140|%s: monobit test failed! [%d]", user, fips140_n1);
		stats_t.monobit++;
		return false;
	}

	/* poker test */
	/*  X = (16/5000) * (E[f(i)]^2, 0<=i<=15) - 5000
	 * -passed if 1.03 < X < 57.4 <-- 140-1
	 * +passwd if 2.16 < X < 46.17 <-- 140-2
	 */
	for(loop=0; loop<16; loop++)
	{
		total += (fips140_pokerbuf[loop]*fips140_pokerbuf[loop]);
	}
	X = (16.0/5000.0) * double(total) - 5001.0;
	if ((fips_version == 2 && (X<=2.16 || X>=46.17)) ||
	    (fips_version == 1 && (X<=1.03 || X>=57.4)))
	{
		dolog(LOG_CRIT, "fips140|%s: poker test failed! [%f]", user, X);
		stats_t.poker++;
		return false;
	}

	/* well, as far as we could see here, all is fine */
	return true;
}

#define fips140_checkinterval(index, min, max)						\
	((runlencounts[(index)][0]<=(min) || runlencounts[(index)][0]>=(max) || \
	  runlencounts[(index)][1]<=(min) || runlencounts[(index)][1]>=(max))	\
	 ? 0 : 1)

/* warning; this one also invokes the short test(!) */
bool fips140::fips140_longtest()
{
	int byteindex;
	int lastbit=0;
	int runlength=0;
	int runlencounts[7][2];
	char nok=0;
	memset(runlencounts, 0x00, sizeof runlencounts);

	/* first see if the shorttest fails. no need to do
	 * the long one if the short one is failing already
	 */
	if (fips140_shorttest() == 0)
	{
		return false;
	}

	/* go trough all 20.000 bits */
	for(byteindex=0; byteindex<(20000/8); byteindex++)
	{
		int bitindex;

		/* get a byte */
		unsigned char curbyte = fips140_rval[byteindex];

		/* test all bits in this byte */
		for(bitindex=0; bitindex<8; bitindex++)
		{
			/* first bit? */
			if (byteindex==0 && bitindex==0)
			{
				lastbit = (curbyte & 128)?1:0;
				runlength = 1;
			}
			else	/* not the first bit, so evaluate */
			{
				int curbit = (curbyte & 128)?1:0;

				/* this bit is the same as the previous one */
				if (curbit == lastbit)
				{
					runlength++;

					/* test for long-run (34 or more bits
					 * with same value) */
					if ((fips_version == 2 && runlength >= 26) ||	/* 140-2 */
					    (fips_version == 1 && runlength >= 34))
					{
						dolog(LOG_CRIT, "fips140|%s: long-run failed! [%d]", user, runlength);
						stats_t.longrun++;
						return false;
					}
				}
				else
				{
					/* remember this bit */
					lastbit = curbit;

					/* keep track of run-lengths */
					if (runlength > 6){runlength=6;}
					(runlencounts[runlength][curbit])++;

					/* reset to runlength=1 */
					runlength = 1;
				}
			}

			/* go the next bit */
			curbyte <<= 1;
		}
	}
	/* take also care of the last run! */
	if (runlength)
	{
		/* keep track of run-lengths */
		if (runlength > 6){runlength=6;}
		runlencounts[runlength][lastbit]++;
	}

	/* now we evaluated all bits, reset new-bits-counter */
	fips140_nnewbits = 0;

	/* now we have the frequencies of all runs */
	/* verify their frequency of occurence */
	if (fips_version == 1)
	{
		nok |= !fips140_checkinterval(1, 2267, 2733);
		nok |= !fips140_checkinterval(2, 1079, 1421);
		nok |= !fips140_checkinterval(3, 502, 748);
		nok |= !fips140_checkinterval(4, 223, 402);
		nok |= !fips140_checkinterval(5, 90, 223);
		nok |= !fips140_checkinterval(6, 90, 223);
	}
	else if (fips_version == 2)
	{
		nok |= !fips140_checkinterval(1, 2343, 2657);
		nok |= !fips140_checkinterval(2, 1135, 1365);
		nok |= !fips140_checkinterval(3, 542, 708);
		nok |= !fips140_checkinterval(4, 251, 373);
		nok |= !fips140_checkinterval(5, 111, 201);
		nok |= !fips140_checkinterval(6, 111, 201);
	}
	if (nok)
	{
		dolog(LOG_CRIT, "fips140|%s: runs-test failed!", user);
		stats_t.runs++;
		return false;
	}

	/* this is a fine set of random values */
	return true;
}

bool fips140::is_ok()
{
	if (fips140_nnewbits >= 2495)
	{
		return fips140_longtest();
	}

	return fips140_shorttest();
}

char *fips140::stats()
{
	static char stats_buffer[4096];

	snprintf(stats_buffer, sizeof stats_buffer, "monobit: %d, poker: %d, longrun: %d, runs: %d",
			stats_t.monobit, stats_t.poker, stats_t.longrun, stats_t.runs);

	return stats_buffer;
}
