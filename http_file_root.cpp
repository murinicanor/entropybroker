#include <map>
#include <string>
#include <vector>

#include "statistics.h"
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
			"   <nav>\n"
			"    <a href=\"/users.html\"><img border=\"0\" alt=\"user data\" src=\"users.png\"/>user data</a>\n"
			"    <a href=\"/stats.html\"><img border=\"0\" alt=\"statistics page\" src=\"statistics.png\"/>statistics</a>\n"
			"    <a href=\"/logfile.html\"><img border=\"0\" alt=\"logfile(s) page\" src=\"logfiles.png\"/>log file</a>\n"
			"    <a href=\"/version.html\"><img border=\"0\" alt=\"version information\" src=\"logo-bw.png\"/>version</a>\n"
			"   </nav>\n" +
			get_style_tail());
}
