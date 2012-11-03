#include <stdlib.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "http_bundle.h"
#include "http_server.h"

http_server::http_server(int fd_in) : fd(fd_in), request_type(static_cast<request_t>(-1))
{
}

http_server::~http_server()
{
	free(request_data);
}

void run()
{
	// retrieve request FIXME
}

request_t http_server::get_request_type()
{
	return request_type;
}

http_bundle * http_server::get_request()
{
	return new http_bundle(request_headers, request_data, request_data_size);
}

void http_server::send_response(http_bundle *response)
{
	// FIXME
}

void http_server::terminate()
{
	close(fd);
}
