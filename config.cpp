#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "config.h"
#include "log.h"

char config_yes_no(char *what)
{
        if (what[0] == '1' || strcasecmp(what, "yes") == 0 || strcasecmp(what, "on") == 0)
        {
                return 1;
        }

        return 0;
}

void load_config(const char *config, config_t *pconfig)
{
        int linenr = 0;
        FILE *fh = fopen(config, "r");
        if (!fh)
                error_exit("error opening configuration file '%s'", config);

	/* set defaults */
	pconfig -> number_of_pools = 14;

	pconfig -> listen_adapter    = (char *)"0.0.0.0";
	pconfig -> listen_port       = 55225;
	pconfig -> listen_queue_size = 5;
	pconfig -> disable_nagle     = 0;
	pconfig -> enable_keepalive  = 1;

	pconfig -> reset_counters_interval    = 60;
	pconfig -> statistics_interval        = 300;
	pconfig -> ping_interval              = 601;
	pconfig -> kernelpool_filled_interval = 3600;

	pconfig -> stats_file = NULL;

	pconfig -> communication_timeout              = 15;
	pconfig -> communication_session_timeout      = 3600; /* 0 for no timeout */
	pconfig -> default_sleep_time_when_pools_fool = 10;
	pconfig -> default_max_sleep_when_pool_fool   = 60;
	pconfig -> default_sleep_when_pools_empty     = 1;
	pconfig -> default_max_sleep_when_pools_empty = 60;
	pconfig -> when_pools_full_allow_submit_interval = 15;

	pconfig -> default_max_bits_per_interval = 16000000;

	pconfig -> ignore_rngtest_fips140 = 0;
	pconfig -> ignore_rngtest_scc = 0;
	pconfig -> scc_threshold = 0.2;

	pconfig -> allow_event_entropy_addition = 1;
	pconfig -> add_entropy_even_if_all_full = 0;
	pconfig -> allow_prng = 0;

	pconfig -> auth_password = NULL;

        for(;;)
        {
		double parvald;
		int parval;
                char read_buffer[4096], *lf, *par;
                char *cmd = fgets(read_buffer, sizeof(read_buffer), fh), *is;
                if (!cmd)
                        break;
                linenr++;

                if (read_buffer[0] == '#' || read_buffer[0] == ';')
                        continue;

		while(*cmd == ' ') cmd++;

                lf = strchr(read_buffer, '\n');
                if (lf) *lf = 0x00;

                is = strchr(read_buffer, '=');
                if (!is)
                        error_exit("invalid line at line %d: '=' missing", linenr);

                *is = 0x00;
                par = is + 1;
		while(*par == ' ') par++;
		parval = atoi(par);
		parvald = atof(par);

		is--;
		while(*is == ' ') { *is = 0x00 ; is--; }

		if (strcmp(cmd, "number_of_pools") == 0)
			pconfig -> number_of_pools = parval;
		else if (strcmp(cmd, "listen_adapter") == 0)
			pconfig -> listen_adapter = strdup(par);
		else if (strcmp(cmd, "password") == 0)
			pconfig -> auth_password = strdup(par);
		else if (strcmp(cmd, "listen_port") == 0)
			pconfig -> listen_port = parval;
		else if (strcmp(cmd, "listen_queue_size") == 0)
			pconfig -> listen_queue_size = parval;
		else if (strcmp(cmd, "disable_nagle") == 0)
			pconfig -> disable_nagle = config_yes_no(par);
		else if (strcmp(cmd, "enable_keepalive") == 0)
			pconfig -> enable_keepalive = config_yes_no(par);
		else if (strcmp(cmd, "reset_counters_interval") == 0)
			pconfig -> reset_counters_interval = parval;
		else if (strcmp(cmd, "statistics_interval") == 0)
			pconfig -> statistics_interval = parval;
		else if (strcmp(cmd, "ping_interval") == 0)
			pconfig -> ping_interval = parval;
		else if (strcmp(cmd, "kernelpool_filled_interval") == 0)
			pconfig -> kernelpool_filled_interval = parval;
		else if (strcmp(cmd, "stats_file") == 0)
			pconfig -> stats_file = strdup(par);
		else if (strcmp(cmd, "communication_timeout") == 0)
			pconfig -> communication_timeout = parval;
		else if (strcmp(cmd, "communication_session_timeout") == 0)
			pconfig -> communication_session_timeout = parval;
		else if (strcmp(cmd, "default_sleep_time_when_pools_fool") == 0)
			pconfig -> default_sleep_time_when_pools_fool = parval;
		else if (strcmp(cmd, "default_max_sleep_when_pool_fool") == 0)
			pconfig -> default_max_sleep_when_pool_fool = parval;
		else if (strcmp(cmd, "default_sleep_when_pools_empty") == 0)
			pconfig -> default_sleep_when_pools_empty = parval;
		else if (strcmp(cmd, "default_max_sleep_when_pools_empty") == 0)
			pconfig -> default_max_sleep_when_pools_empty = parval;
		else if (strcmp(cmd, "default_max_bits_per_interval") == 0)
			pconfig -> default_max_bits_per_interval = parval;
		else if (strcmp(cmd, "ignore_rngtest_fips140") == 0)
			pconfig -> ignore_rngtest_fips140 = config_yes_no(par);
		else if (strcmp(cmd, "ignore_rngtest_scc") == 0)
			pconfig -> ignore_rngtest_scc = config_yes_no(par);
		else if (strcmp(cmd, "allow_event_entropy_addition") == 0)
			pconfig -> allow_event_entropy_addition = config_yes_no(par);
		else if (strcmp(cmd, "add_entropy_even_if_all_full") == 0)
			pconfig -> add_entropy_even_if_all_full = config_yes_no(par);
		else if (strcmp(cmd, "allow_prng") == 0)
			pconfig -> allow_prng = config_yes_no(par);
		else if (strcmp(cmd, "scc_threshold") == 0)
			pconfig -> scc_threshold = parvald;
		else if (strcmp(cmd, "when_pools_full_allow_submit_interval") == 0)
			pconfig -> when_pools_full_allow_submit_interval = parval;
		else
			error_exit("%s=%s not understood", cmd, par);
	}

	dolog(LOG_DEBUG, "read %d configuration file lines", linenr);

	fclose(fh);
}
