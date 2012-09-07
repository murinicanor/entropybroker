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

long int byte_cnt = -1, total_byte_cnt = -1;
double cur_start_ts = -1.0, start_ts = -1.0;

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
	cur_start_ts = start_ts = get_ts();

	byte_cnt = total_byte_cnt = 0;
}

void update_showbps(int count)
{
	double now_ts = get_ts();

	byte_cnt += count;
	total_byte_cnt += count;

	if ((now_ts - cur_start_ts) >= 1.0)
	{
		double diff_t = now_ts - cur_start_ts;
		double global_diff_t = now_ts - start_ts;

		dolog(LOG_INFO, "Total # bytes: %ld, global avg/s: %f, run time: %fs, interval: %fs, avg/s: %f\n", total_byte_cnt, double(total_byte_cnt) / global_diff_t, global_diff_t, diff_t, double(byte_cnt) / diff_t);

		cur_start_ts = now_ts;

		byte_cnt = 0;
	}
}
