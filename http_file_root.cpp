#include <map>
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

http_bundle * http_file_root::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;

	return new http_bundle(reply_headers,
			get_style_header() + 
			"<TABLE CLASS=\"table2\" WIDTH=100%><TR><TD>\n"
			"<A HREF=\"stats.html\">stats</A><BR><A HREF=\"version.html\">version</A>\n"
			"</TD></TR></TABLE>\n" +
			get_style_tail());
}
