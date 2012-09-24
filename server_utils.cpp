// SVN: $Id$
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <stdlib.h>
#include <openssl/blowfish.h>
#include <string.h>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"

long int byte_cnt = 0, total_byte_cnt = 0;
double total_time = 0.0, last_ts = 0.0, last_emit_ts = 0.0;

void emit_buffer_to_file(char *file, unsigned char *data, size_t n_bytes)
{
	FILE *fh = fopen(file, "a+");
	if (!fh)
		error_exit("Error opening %s for append access", file);

	if (fwrite(data, 1, n_bytes, fh) != n_bytes)
		error_exit("Short write to %s", file);

	fclose(fh);
}

void init_showbps()
{
	byte_cnt = total_byte_cnt = 0;

	total_time = 0.0;

	last_emit_ts = get_ts();
}

void set_showbps_start_ts()
{
	last_ts = get_ts();
}

void update_showbps(int count)
{
	double now_ts = get_ts();
	double diff_ts = now_ts - last_ts;

	byte_cnt += count;
	total_byte_cnt += count;

	total_time += diff_ts;

	if (now_ts - last_emit_ts >= 1.0)
	{
		dolog(LOG_INFO, "Total # bytes: %ld, global avg/s: %f, run time: %fs, interval: %fs, avg/s: %f", total_byte_cnt, double(total_byte_cnt) / total_time, total_time, diff_ts, double(byte_cnt) / diff_ts);

		byte_cnt = 0;

		last_emit_ts = now_ts;
	}
}
