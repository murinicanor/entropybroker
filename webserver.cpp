#include "httpserver.h"
#include "webserver.h"

webserver::webserver(std::string listen_adapter, int listen_port) : fd(-1)
{
	// FIXME
}

webserver::~webserver()
{
	if (fd != -1)
		close(fd);
}
