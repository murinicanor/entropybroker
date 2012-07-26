#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <time.h>

#include "error.h"


char log_console = 1;
char *log_file = NULL;
char log_syslog = 0;

void dolog(int level, const char *format, ...)
{
        char buffer[4096];
        va_list ap;
        time_t now = time(NULL);
        char *timestr = ctime(&now);
        char *dummy = strchr(timestr, '\n');
        if (dummy) *dummy = 0x00;

        va_start(ap, format);
        vsnprintf(buffer, sizeof(buffer), format, ap);
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

	if (log_syslog && level < 6)
		syslog(level, "%s", buffer);
}

void set_logging_parameters(char console, char *file, char sl)
{
	log_console = console;
	log_file = file;
	log_syslog = sl;
}
