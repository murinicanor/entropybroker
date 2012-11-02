#include "http_server.h"

http_server::http_server(int fd_in) : fd(fd_in), request_type(-1), request_data(NULL), request_data_len(0)
{
	// retrieve request FIXME
}

http_server::~http_server()
{
	free(request_data);
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
