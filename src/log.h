#include <syslog.h>

void dolog(int level, const char *format, ...);
void set_logging_parameters(bool console, char *file, bool sl, int ll);
void set_loglevel(int ll);
