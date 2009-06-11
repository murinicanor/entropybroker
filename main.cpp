#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "pool.h"
#include "client.h"
#include "utils.h"
#include "log.h"
#include "handle_pool.h"

int main(int argc, char *argv[])
{
	int loop;
	pool **pools;
	int n_pools = 14;

	signal(SIGPIPE, SIG_IGN);

//	set_logging_parameters(1, "LOG", 0);

	pools = (pool **)malloc(sizeof(pool *) * n_pools);
	for(loop=0; loop<n_pools; loop++)
		pools[loop] = new pool();

{
unsigned char *buffer;

printf("total bits; %d\n", get_bit_sum(pools, n_pools));
for(loop=0; loop<1000; loop++)
	int event_bits = add_event(pools, n_pools, lrand48());
printf("total bits; %d\n", get_bit_sum(pools, n_pools));
//printf("%d\n", get_bits_from_pools(1000, pools, n_pools, &buffer, 0));
//exit(1);
}
#if 0
for(;;)
{
	static int cnt = 0;
	unsigned char *buffer;

	get_bits_from_pools(myrand(240) + 1, pools, n_pools, &buffer, 0);
	free(buffer);

	if (++cnt % 10000 == 0)
		printf("%d\r", cnt);

	if (get_bit_sum(pools, n_pools) < 8)
	{
		for(loop=0; loop<1000; loop++)
			int event_bits = add_event(pools, n_pools, myrand(4000000));
	}
}
#endif
	int event_bits = add_event(pools, n_pools, get_ts());
	dolog(LOG_DEBUG, "added %d bits of startup-event-entropy to pool", event_bits);

	main_loop(pools, n_pools, 60, "0.0.0.0", 55225);

	return 0;
}
