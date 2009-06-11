#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "error.h"
#include "pool.h"
#include "client.h"
#include "utils.h"
#include "log.h"
#include "handle_pool.h"

void help(void)
{
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
        printf("-n        do not fork\n");
}

int main(int argc, char *argv[])
{
	int loop;
	pool **pools;
	int n_pools = 14;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;

	printf("eb v " VERSION ", (C) 2009 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "l:sn")) != -1)
	{
		switch(c)
		{
			case 's':
				log_syslog = 1;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = 1;
				log_console = 1;
				break;

			default:
				help();
				return 1;
		}
	}

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	signal(SIGPIPE, SIG_IGN);

	pools = (pool **)malloc(sizeof(pool *) * n_pools);
	for(loop=0; loop<n_pools; loop++)
		pools[loop] = new pool();

#if 0
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
#endif
	dolog(LOG_DEBUG, "added %d bits of startup-event-entropy to pool", add_event(pools, n_pools, get_ts()));

	main_loop(pools, n_pools, 60, "0.0.0.0", 55225);

	return 0;
}
