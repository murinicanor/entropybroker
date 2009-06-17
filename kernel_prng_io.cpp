#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <asm/types.h>
#include <linux/random.h>

#include "error.h"
#include "utils.h"
#include "kernel_prng_io.h"

int kernel_rng_read_blocking(unsigned char *buffer, int n)
{
	int fd = open(DEV_RANDOM, O_RDONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_RANDOM);

	if (READ(fd, (char *)buffer, n) != n)
		return -1;

	close(fd);

	return n;
}

int kernel_rng_read_non_blocking(unsigned char *buffer, int n)
{
	int rc;
	int fd = open(DEV_URANDOM, O_RDONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_URANDOM);

	for(;;)
	{
		rc = read(fd, buffer, n);

		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			close(fd);

			error_exit("error reading from %s", DEV_URANDOM);
		}

		break;
	}

	close(fd);

	return rc;
}

int kernel_rng_write_non_blocking(unsigned char *buffer, int n)
{
	int rc;
	int fd = open(DEV_URANDOM, O_WRONLY);
	if (fd == -1)
		return -1;

	for(;;)
	{
		rc = write(fd, buffer, n);

		if (rc == -1)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;

			close(fd);

			error_exit("error writing to %s", DEV_URANDOM);
		}

		break;
	}

	close(fd);

	return rc;
}

int kernel_rng_get_entropy_count()
{
	int n_bits;
	int fd = open(DEV_RANDOM, O_RDONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_RANDOM);

	if (ioctl(fd, RNDGETENTCNT, &n_bits) == -1)
		error_exit("ioctl(RNDGETENTCNT) failed");

	close(fd);

	return n_bits;
}

int kernel_rng_add_entropy(unsigned char *data, int n, int n_bits)
{
	int total_size;
        struct rand_pool_info *output;
	int fd = open(DEV_RANDOM, O_WRONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_RANDOM);

	total_size = sizeof(struct rand_pool_info) + n;
        output = (struct rand_pool_info *)malloc(total_size);
        if (!output)
                error_exit("malloc failure in kernel_rng_add_entropy_no_bitcount_increase(%d)", n);

	output -> entropy_count = n_bits;
	output -> buf_size      = n;
	memcpy(&(output -> buf[0]), data, n);

	if (ioctl(fd, RNDADDENTROPY, output) == -1)
		error_exit("ioctl(RNDADDENTROPY) failed!");

	free(output);

	close(fd);

	return 0;
}

int kernel_rng_get_max_entropy_count(void)
{
	int bit_count;
	FILE *fh = fopen(PROC_POOLSIZE, "r");
	if (!fh)
		error_exit("Failed to open %s", PROC_POOLSIZE);

	if (fscanf(fh, "%d", &bit_count) != 1)
		error_exit("Failed to read from %s", PROC_POOLSIZE);

	fclose(fh);

	return bit_count;
}
