#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>

#include "error.h"
#include "utils.h"
#include "data_store_int.h"

data_store_int::data_store_int(int n_samples_in, int interval_in) : n_samples(n_samples_in), interval(interval_in)
{
	values = (long long int *)calloc(n_samples, sizeof(long long int));
	counts = (int *)calloc(n_samples, sizeof(int));
	valid = (bool *)calloc(n_samples, sizeof(bool));

	cur_t = 0;
}

data_store_int::data_store_int(std::string file)
{
	FILE *fh = fopen(file.c_str(), "r");
	if (!fh)
		error_exit("failed to open %s", file.c_str());

	if (!get_int(fh, &n_samples))
		error_exit("short read on %s", file.c_str());
	if (!get_int(fh, &interval))
		error_exit("short read on %s", file.c_str());
	if (!get_int(fh, &cur_t))
		error_exit("short read on %s", file.c_str());

	values = (long long int *)calloc(n_samples, sizeof(long long int));
	counts = (int *)calloc(n_samples, sizeof(int));
	valid = (bool *)calloc(n_samples, sizeof(bool));

	for(int index=0; index<n_samples; index++)
	{
		if (!get_long_long_int(fh, &values[index]))
			error_exit("short read on %s", file.c_str());
		if (!get_int(fh, &counts[index]))
			error_exit("short read on %s", file.c_str());
		if (!get_bool(fh, &valid[index]))
			error_exit("short read on %s", file.c_str());
	}

	fclose(fh);
}

data_store_int::~data_store_int()
{
	free(counts);
	free(values);
	free(valid);
}

void data_store_int::dump(std::string file)
{
	FILE *fh = fopen(file.c_str(), "wb");
	if (!fh)
		error_exit("faile to create file %s", file.c_str());

	put_int(fh, n_samples);
	put_int(fh, interval);
	put_int(fh, cur_t);

	for(int index=0; index<n_samples; index++)
	{
		put_long_long_int(fh, values[index]);
		put_int(fh, counts[index]);
		put_bool(fh, valid[index]);
	}

	fclose(fh);
}

int data_store_int::init_data(int t)
{
	int cur_index = (t / interval) % n_samples;
	int prev_index = cur_t != -1 ? (cur_t / interval) % n_samples : -1;

	if (cur_index != prev_index && prev_index != -1)
	{
		// if the interval between now and previous value
		// is more than a second, then invalidate values
		// in between
		if (cur_index > prev_index)
		{
			int n = (cur_index - prev_index) - 1;

			if (n > 0)
			{
				memset(&values[prev_index + 1], 0x00, sizeof(long long int) * n);
				memset(&counts[prev_index + 1], 0x00, sizeof(int) * n);
				memset(&valid[prev_index + 1], 0x00, sizeof(bool) * n);
			}
		}
		else
		{
			int n = n_samples - prev_index;
			memset(&values[prev_index], 0x00, sizeof(long long int) * n);
			memset(&counts[prev_index], 0x00, sizeof(int) * n);
			memset(&valid[prev_index], 0x00, sizeof(bool) * n);

			memset(&values[0], 0x00, sizeof(long long int) * cur_index);
			memset(&counts[0], 0x00, sizeof(int) * cur_index);
			memset(&valid[0], 0x00, sizeof(bool) * cur_index);
		}

		values[cur_index] = 0;
		counts[cur_index] = 0;
		valid[cur_index] = true;
	}

	cur_t = t;

	return cur_index;
}

void data_store_int::add_avg(int t, int value)
{
	int index = init_data(t);

	values[index] += value;
	counts[index]++;
}

void data_store_int::add_sum(int t, int value)
{
	int index = init_data(t);

	values[index] += value;
	counts[index] = 1;
}

bool data_store_int::get(int index, double *value)
{
	if (counts[index])
	{
		*value = double(values[index]) / double(counts[index]);

		return true;
	}

	return false;
}

void data_store_int::get_data(long int **t, double **v, int *n)
{
	int offset_index = (cur_t / interval) % n_samples;

	*t = (long int *)malloc(sizeof(long int) * n_samples);
	*v = (double *)malloc(sizeof(double) * n_samples);
	*n = 0;

	long int start_t = cur_t - n_samples * interval;
	for(int index=0; index<n_samples; index++)
	{
		int cur_index = (offset_index + 1 + index) % n_samples;

		if (valid[cur_index])
		{
			(*t)[*n] = start_t + index * interval;
			(*v)[*n] = double(values[cur_index]) / double(counts[cur_index]);
			(*n)++;
		}
	}
}
