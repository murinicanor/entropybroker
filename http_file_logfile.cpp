#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "utils.h"
#include "hasher.h"
#include "math.h"
#include "stirrer.h"
#include "random_source.h"
#include "fips140.h"
#include "scc.h"
#include "hasher_type.h"
#include "stirrer_type.h"
#include "pool_crypto.h"
#include "pool.h"
#include "pools.h"
#include "config.h"
#include "encrypt_stream.h"
#include "users.h"
#include "statistics.h"
#include "statistics_global.h"
#include "handle_client.h"
#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_logfile.h"

http_file_logfile::http_file_logfile(statistics_global *ps_in) : ps(ps_in)
{
}

http_file_logfile::~http_file_logfile()
{
}

std::string http_file_logfile::get_url()
{
	return "/logfile.html";
}

std::string http_file_logfile::get_meta_type()
{
	return "text/html";
}

http_bundle * http_file_logfile::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;

	std::string content = get_style_header();

	content += generate_logging_table(ps, "");

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
