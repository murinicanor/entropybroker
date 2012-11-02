#include "httpserver.h"

httpserver::httpserver(int fd_in) : fd(fd_in), request_type(-1), request_data(NULL), request_data_len(0)
{
	// retrieve request FIXME
}

httpserver::~httpserver()
{
	free(request_data);
}

request_t httpserver::get_request_type()
{
	return request_type;
}

std::vector<std::string> httpserver::get_request_headers()
{
	return request_headers;
}

int httpserver::get_request_data_size()
{
	return request_data_size;
}

unsigned char *httpserver::get_request_data()
{
	return request_data;
}

void httpserver::send_response(std::vector<std::string> response_headers, unsigned char *response_data, int response_data_len)
{
	// FIXME
}

void httpserver::terminate()
{
	close(fd);
}
