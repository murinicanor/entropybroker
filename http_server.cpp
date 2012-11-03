#include <errno.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "utils.h"
#include "http_request_t.h"
#include "http_bundle.h"
#include "http_server.h"

http_server::http_server(int fd_in) : fd(fd_in), request_type(static_cast<http_request_t>(-1))
{
	request_data = reinterpret_cast<unsigned char *>(malloc(HTTP_SERVER_READ_SIZE + 1));
	request_data_size = 0;
	request_type = HR_FAIL;

	char *headers_end = NULL;
	bool crlf = true;

	do
	{
		int rc = read(fd_in, &request_data[request_data_size], HTTP_SERVER_READ_SIZE);
		if (rc == -1 || rc == 0)
		{
			if (rc == -1 && errno == EINTR)
				continue;

			dolog(LOG_INFO, "HTTP: short read");
			break;
		}

		request_data_size += rc;
		request_data = reinterpret_cast<unsigned char *>(realloc(request_data, request_data_size + HTTP_SERVER_READ_SIZE + 1));

		request_data[request_data_size] = 0x00;

		headers_end = strstr(reinterpret_cast<char *>(request_data), "\r\n\r\n");
		if (!headers_end)
		{
			headers_end = strstr(reinterpret_cast<char *>(request_data), "\n\n");
			if (headers_end)
				crlf = false;
		}
	}
	while(headers_end == NULL);

	if (headers_end)
	{
		// get headers from request
		*headers_end = 0x00;

		const char *line_end = crlf ? "\r\n" : "\n";

		char **headers = NULL;
		int n_headers = 0;
		split_string(reinterpret_cast<char *>(request_data), line_end, &headers, &n_headers);

		for(int index=0; index<n_headers; index++)
		{
			request_headers.push_back(headers[index]);
			free(headers[index]);
		}

		// memmove read data (if any) to front
		int headers_size = int(headers_end - reinterpret_cast<char *>(request_data)) + (crlf ? 4 : 2);
		int bytes_left = request_data_size - headers_size;
		if (bytes_left)
		{
			memmove(request_data, &request_data[headers_size], bytes_left);
			request_data_size -= headers_size;
		}
		else
		{
			request_data_size = 0;
		}

		// set request_type for GET/POST

		if (request_headers.at(0).length() >= 4)
		{
			std::string req = request_headers.at(0).substr(0, 4);

			if (req == "GET ")
				request_type = HR_GET;
			else if (req == "POST")
				request_type = HR_POST;
		}
	}
}

http_server::~http_server()
{
	free(request_data);
}

http_request_t http_server::get_request_type()
{
	return request_type;
}

http_bundle * http_server::get_request()
{
	return new http_bundle(request_headers, request_data, request_data_size);
}

void http_server::send_response(int status_code, http_bundle *response)
{
	// FIXME

	std::string result;
}
