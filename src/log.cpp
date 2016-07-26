#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <time.h>

#include "error.h"

bool log_console = true;
char *log_file = NULL;
bool log_syslog = false;
int log_level = 1;

void dolog(int level, const char *format, ...)
{
	if (level <= log_level)
	{
		char buffer[4096];
		va_list ap;
		time_t now = time(NULL);

		char timestr[256] = { 0 };
		ctime_r(&now, timestr); // can't set a limit so hopefully this 256 is enough!
		char *dummy = strchr(timestr, '\n');
		if (dummy) *dummy = 0x00;

		va_start(ap, format);
		vsnprintf(buffer, sizeof buffer, format, ap);
		va_end(ap);

		if (log_console)
			printf("%s]%d| %s\n", timestr, level, buffer);

		if (log_file)
		{
			FILE *fh = fopen(log_file, "a+");
			if (!fh)
			{
				syslog(LOG_CRIT, "error accessing logfile %s: %m", log_file);
				fprintf(stderr, "error accessing logfile %s: %s", log_file, strerror(errno));
				exit(1);
			}

			fprintf(fh, "%s]%d| %s\n", timestr, level, buffer);

			fclose(fh);
		}

		if (log_syslog)
			syslog(level, "%s", buffer);
	}
}

void set_logging_parameters(bool console, char *file, bool sl, int ll)
{
	log_console = console;
	log_file = file;
	log_syslog = sl;
	log_level = ll;

	if (ll < 0)
	{
		ll = 0;

		error_exit("Log level must be >= 0");
	}
}

void set_loglevel(int ll)
{
	log_level = ll;
}
