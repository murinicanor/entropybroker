#include <syslog.h>

void dolog(int level, const char *format, ...);
void set_logging_parameters(char console, char *file, char sl);
