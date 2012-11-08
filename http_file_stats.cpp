#include <string>
#include <vector>

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
#include "handle_client.h"
#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_stats.h"

http_file_stats::http_file_stats(std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in) : clients(clients_in), clients_mutex(clients_mutex_in)
{
}

http_file_stats::~http_file_stats()
{
}

std::string http_file_stats::get_url()
{
	return "/stats.html";
}

std::string http_file_stats::get_meta_type()
{
	return "text/html";
}

http_bundle * http_file_stats::do_request(http_request_t request_type, http_bundle *request_details)
{
	std::vector<std::string> reply_headers;

	return new http_bundle(reply_headers, "");
}
