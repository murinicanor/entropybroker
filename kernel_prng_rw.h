// SVN: $Id$
int kernel_rng_read_blocking(unsigned char *buffer, int n);
int kernel_rng_read_non_blocking(unsigned char *buffer, int n);
int kernel_rng_write_non_blocking(unsigned char *buffer, int n);
