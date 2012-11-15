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
			"<A HREF=\"/stats.html\"><IMG ALIGN=\"middle\" SRC=\"statistics.png\" BORDER=0>stats</A><BR><BR>\n"
			"<A HREF=\"/logfile.html\"><IMG ALIGN=\"middle\" SRC=\"logfiles.png\" BORDER=0>log file</A><BR><BR>\n"
			"<A HREF=\"/version.html\"><IMG ALIGN=\"middle\" SRC=\"logo-bw.png\" BORDER=0>version</A>\n"
			"</TD></TR></TABLE>\n" +
			get_style_tail());
}
