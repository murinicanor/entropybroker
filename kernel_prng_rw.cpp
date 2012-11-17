// SVN: $Revision$
#include <stdio.h>
#include <string>
#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/random.h>

#include "error.h"
#include "utils.h"
#include "kernel_prng_io.h"

int kernel_rng_read_blocking(unsigned char *buffer, int n)
{
	int fd = open(DEV_RANDOM, O_RDONLY);
	if (fd == -1)
		error_exit("Failed to open %s", DEV_RANDOM);

	int rc = -1;
	if (READ(fd, buffer, n) == n)
		rc = n;

	close(fd);

	return rc;
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

			error_exit("error writing to %s", DEV_URANDOM);
		}

		break;
	}

	close(fd);

	return rc;
}
