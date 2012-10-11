// SVN: $Revision$
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <execinfo.h>

#include "log.h"
#include "utils.h"

void error_exit(const char *format, ...)
{
	char buffer[4096];
	va_list ap;

	va_start(ap, format);
	vsnprintf(buffer, sizeof buffer, format, ap);
	va_end(ap);

	set_loglevel(1);
	dolog(LOG_EMERG, "FATAL|%s|%s", get_current_thread_name().c_str(), buffer);
	dolog(LOG_EMERG, "FATAL|%s|errno at that time: %d (%s)", get_current_thread_name().c_str(), errno, strerror(errno));

	void *trace[128];
	int trace_size = backtrace(trace, 128);
	char **messages = backtrace_symbols(trace, trace_size);
	dolog(LOG_EMERG, "Execution path:");
	for(int index=0; index<trace_size; ++index)
		dolog(LOG_EMERG, "%d %s", index, messages[index]);

	exit(EXIT_FAILURE);
}
