#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

#include "log.h"

void error_exit(const char *format, ...)
{
	char buffer[4096];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof(buffer), format, ap);
	va_end(ap);

	dolog(LOG_EMERG, "FATAL|%s\n", buffer);
	dolog(LOG_EMERG, "errno at that time: %d (%s)", errno, strerror(errno));

	exit(EXIT_FAILURE);
}
