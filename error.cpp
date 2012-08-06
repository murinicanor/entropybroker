#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>
#include <openssl/err.h>

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

	ERR_load_crypto_strings();
	for(;;)
	{
		unsigned long ose = ERR_get_error();
		if (ose == 0)
			break;

		dolog(LOG_CRIT, "OpenSSL error: %s", ERR_error_string(ose, NULL));
	}

	exit(EXIT_FAILURE);
}
