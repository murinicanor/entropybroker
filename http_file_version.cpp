#include <map>
#include <string>
#include <vector>

#include "statistics.h"
#include "statistics_global.h"
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

std::string http_file_version::get_meta_type()
{
	return "text/html";
}

http_bundle * http_file_version::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;

	return new http_bundle(reply_headers, get_style_header() + "<H2>Entropy Broker v" VERSION "</H2>$Id$" + get_style_tail());
}
