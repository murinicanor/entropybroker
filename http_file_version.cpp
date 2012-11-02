#include "http_bundle.h"
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

http_bundle * http_file_version::do_request(request_t request_type, http_bundle *request_details)
{
	// "<HTML><BODY>" VERSION "</BODY></HTML>"
}
