// SVN: $Id$
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <execinfo.h>
#include <openssl/err.h>

#include "log.h"

void error_exit(const char *format, ...)
{
	char buffer[4096];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof buffer, format, ap);
	va_end(ap);

	dolog(LOG_EMERG, "FATAL|%s\n", buffer);
	dolog(LOG_EMERG, "errno at that time: %d (%s)", errno, strerror(errno));

	ERR_load_crypto_strings();
	for(;;)
	{
		unsigned long ose = ERR_get_error();
		if (ose == 0)
			break;

		dolog(LOG_CRIT, "OpenSSL error: %s", ERR_error_string(ose, NULL));
	}

	void *trace[128];
	int trace_size = backtrace(trace, 128);
	char **messages = backtrace_symbols(trace, trace_size);
	printf("\nExecution path:\n");
	for(int index=0; index<trace_size; ++index)
		printf("%d %s\n", index, messages[index]);

	exit(EXIT_FAILURE);
}
