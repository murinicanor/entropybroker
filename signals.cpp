#include <signal.h>

#include "error.h"

static int signal_hup = 0;

void signal_handler(int sig)
{
	if (sig == SIGHUP)
		signal_hup = 1;

	if (sig == SIGBUS)
		error_exit("hardware issue, terminating");

	signal(sig, signal_handler);
}

int is_SIGHUP(void)
{
	return signal_hup;
}

void reset_SIGHUP(void)
{
	signal_hup = 0;
}

void set_signal_handlers(void)
{
	signal(SIGPIPE, SIG_IGN);

	signal(SIGHUP, signal_handler);
	signal(SIGBUS, signal_handler);
}
