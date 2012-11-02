#include "http_server.h"
#include "web_server.h"

web_server::web_server(std::string listen_adapter, int listen_port) : fd(-1)
{
	// FIXME
}

web_server::~web_server()
{
	if (fd != -1)
		close(fd);
}
