#include <errno.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "http_request_t.h"
#include "http_bundle.h"
#include "http_server.h"

http_server::http_server(int fd_in) : fd(fd_in), request_type(static_cast<http_request_t>(-1))
{
	request_data = reinterpret_cast<unsigned char *>(malloc(HTTP_SERVER_READ_SIZE + 1));
	request_data_size = 0;
	request_type = HR_FAIL;

	do
	{
		int rc = read(fd_in, &request_data[request_data_size], HTTP_SERVER_READ_SIZE);
		if (rc == -1 || rc == 0)
		{
			if (rc == -1 && errno == EINTR)
				continue;

			free(request_data);
			request_data = NULL;

			dolog(LOG_INFO, "HTTP: short read");
			break;
		}

		request_data_size += rc;
		request_data = reinterpret_cast<unsigned char *>(realloc(request_data, request_data_size + HTTP_SERVER_READ_SIZE + 1));

		request_data[request_data_size] = 0x00;
	}
	while(strstr(reinterpret_cast<char *>(request_data), "\r\n\r\n") == NULL);

	// get headers FIXME
	// memmove read data (if any) to front
	// decrease size with headers-size
	// set request_type
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
}
