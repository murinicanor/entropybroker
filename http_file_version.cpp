#include <string>
#include <vector>

#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_version.h"

http_file_version::http_file_version()
{
}

http_file_version::~http_file_version()
{
}

std::string http_file_version::get_url()
{
	return "/version.html";
}

http_bundle * http_file_version::do_request(http_request_t request_type, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;
	reply_headers.push_back("HTTP/1.0 200 Found\r\n");
	reply_headers.push_back("Connection: close\r\n");
	reply_headers.push_back("Content-Type: text/html\r\n");

	http_bundle *result = new http_bundle(reply_headers, "<HTML><BODY>Entropy Broker v" VERSION "</BODY></HTML>");

	return result;
}
