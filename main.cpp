#include <sys/time.h>
#include <stdio.h>
#include "pool.h"

double get_ts(void)
{
        struct timeval ts;

        if (gettimeofday(&ts, NULL) == -1)
		printf("get_ts failed\n");

        return (((double)ts.tv_sec) + ((double)ts.tv_usec)/1000000.0);
}


int main(int argc, char *argv[])
{
	pool p;
	int loop;
	unsigned char buffer[8] = { "test" };
	double start, end;
	const int n = 1024*1024;

	p.add_entropy_data(buffer);

	start = get_ts();

	for(loop=0; loop<(n / 8); loop++)
		p.get_entropy_data(buffer);

	end = get_ts();

	printf("%f s/byte\n", (end - start) / (double)n);
	printf("%f bps\n", (double)n / (end - start));

	return 0;
}
