#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>
#include <string>
#include <openssl/blowfish.h>

#include "error.h"
#include "math.h"
#include "ivec.h"
#include "pool.h"
#include "fips140.h"
#include "scc.h"
#include "config.h"
#include "pools.h"
#include "handle_client.h"
#include "utils.h"
#include "log.h"
#include "signals.h"
#include "auth.h"

const char *pid_file = PID_DIR "/entropy_broker.pid";

void seed(pools *ppools)
{
	int n = 0, dummy;

	n += ppools -> add_event(get_ts_ns(), NULL, 0); 

	dummy = getpid();
	n += ppools -> add_event(get_ts_ns(), (unsigned char *)&dummy, sizeof(dummy));

	dolog(LOG_DEBUG, "added %d bits of startup-event-entropy to pool", n);
}

void help(void)
{
	printf("-c file   config-file to read (default: " CONFIG "\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
	printf("-S        statistics-file to log to\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
}

int main(int argc, char *argv[])
{
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *stats_file = NULL;
	fips140 *eb_output_fips140 = new fips140();
	scc *eb_output_scc = new scc();
	const char *config_file = CONFIG;
	config_t config;

	memset(&config, 0x00, sizeof(config));

	printf("entropy_broker v " VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	eb_output_fips140 -> set_user((char *)"output");
	eb_output_scc     -> set_user((char *)"output");

	while((c = getopt(argc, argv, "hP:c:S:l:sn")) != -1)
	{
		switch(c)
		{
			case 'P':
				pid_file = optarg;
				break;

			case 'c':
				config_file = optarg;
				break;

			case 'S':
				stats_file = optarg;
				break;

			case 's':
				log_syslog = true;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = true;
				log_console = true;
				break;

			default:
				help();
				return 1;
		}
	}

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog);

	load_config(config_file, &config);
	if (stats_file)
		config.stats_file = stats_file;

	if (config.auth_password == NULL)
	{
		fprintf(stderr, "No password set in configurationfile\n");
		return 1;
	}

	eb_output_scc -> set_threshold(config.scc_threshold);

	bit_count_estimator *bce = new bit_count_estimator(config.bitcount_estimator);

	pools *ppools = new pools(std::string(CACHE_DIR), config.max_number_of_mem_pools, config.max_number_of_disk_pools, config.min_store_on_disk_n, bce);

	dolog(LOG_DEBUG, "Blowfish options: %s", BF_options());

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	set_signal_handlers();

	seed(ppools);

	main_loop(ppools, &config, eb_output_fips140, eb_output_scc);

	printf("Dumping pool contents to cache-file\n");
	delete ppools;

	unlink(pid_file);

	printf("Finished\n");

	return 0;
}
