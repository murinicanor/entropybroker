// SVN: $Id$
#include <signal.h>
#include <stdlib.h>

#include "error.h"

static int signal_hup = 0, signal_exit = 0;

void signal_handler(int sig)
{
	if (sig == SIGHUP)
		signal_hup = 1;

	if (sig == SIGTERM || sig == SIGQUIT || sig == SIGINT)
		signal_exit = 1;

	if (sig == SIGBUS)
		error_exit("hardware issue, terminating");

	if (sig == SIGUSR2)
		exit(0);

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

int is_SIGEXIT(void)
{
	return signal_exit;
}

void set_signal_handlers(void)
{
	signal(SIGPIPE, SIG_IGN);

	signal(SIGHUP, signal_handler);
	signal(SIGBUS, signal_handler);

	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGINT , signal_handler);

	signal(SIGUSR2, signal_handler);
}
