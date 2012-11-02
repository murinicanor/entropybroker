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

std::vector<std::string> http_server::get_request_headers()
{
	return request_headers;
}

int http_server::get_request_data_size()
{
	return request_data_size;
}

unsigned char *http_server::get_request_data()
{
	return request_data;
}

void http_server::send_response(std::vector<std::string> response_headers, unsigned char *response_data, int response_data_len)
{
	// FIXME
}

void http_server::terminate()
{
	close(fd);
}
