#include <string>
#include <vector>

#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"

http_file::http_file()
{
}

http_file::~http_file()
{
}

std::string http_file::get_url()
{
	return "?";
}

http_bundle * http_file::do_request(http_request_t request_type, http_bundle *request_details)
{
	return NULL;
}
