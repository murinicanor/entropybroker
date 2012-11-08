#include <string>
#include <vector>

#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_root.h"

http_file_root::http_file_root()
{
}

http_file_root::~http_file_root()
{
}

std::string http_file_root::get_url()
{
	return "/";
}

std::string http_file_root::get_meta_type()
{
	return "text/html";
}

http_bundle * http_file_root::do_request(http_request_t request_type, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;

	return new http_bundle(reply_headers, "<HTML><BODY><A HREF=\"stats.html\">stats</A><BR><A HREF=\"version.html\">version</A></BODY></HTML>");
}
