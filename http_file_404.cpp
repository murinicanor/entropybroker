#include <string>
#include <vector>

#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_404.h"

http_file_404::http_file_404()
{
}

http_file_404::~http_file_404()
{
}

std::string http_file_404::get_url()
{
	return "/404.html";
}

std::string http_file_404::get_meta_type()
{
	return "text/html";
}

http_bundle * http_file_404::do_request(http_request_t request_type, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;

	http_bundle *result = new http_bundle(reply_headers, "<HTML><BODY>vier nul vier</BODY></HTML>");

	return result;
}
