#include <map>
#include <string>
#include <time.h>
#include <vector>
#include <gd.h>

#include "log.h"
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
#include "handle_client.h"
#include "data_store_int.h"
#include "data_logger.h"
#include "graph.h"
#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_graph_data_logger.h"

http_file_graph_data_logger::http_file_graph_data_logger(data_logger *dl_in) : dl(dl_in)
{
	g = new graph(FONT);
}

http_file_graph_data_logger::~http_file_graph_data_logger()
{
	delete g;
}

std::string http_file_graph_data_logger::get_url()
{
	return "/graph.png";
}

std::string http_file_graph_data_logger::get_meta_type()
{
	return "image/png";
}

http_bundle * http_file_graph_data_logger::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	std::map<std::string, std::string> request_parameters = split_parameters(request_url);
	std::map<std::string, std::string>::iterator it = request_parameters.find("type");
	std::string type = "mem_pool_counts";
	if (it != request_parameters.end())
		type = it -> second.c_str();

	int width = 640, height = 240;

	it = request_parameters.find("width");
	if (it != request_parameters.end())
		width = mymax(240, atoi(it -> second.c_str()));

	it = request_parameters.find("height");
	if (it != request_parameters.end())
		height = mymax(200, atoi(it -> second.c_str()));

	std::string title = type;

	std::vector<std::string> reply_headers;

	long int *t = NULL;
	double *v = NULL;
	int n = 0;

	if (type == "mem_pool_counts")
		dl -> get_mem_pool_counts(&t, &v, &n);
	else if (type == "dsk_pool_counts")
		dl -> get_dsk_pool_counts(&t, &v, &n);
	else if (type == "connection_counts")
		dl -> get_connection_counts(&t, &v, &n);
	else if (type == "mem_pools_bitcount")
		dl -> get_pools_bitcounts(&t, &v, &n);
	else if (type == "dsk_pools_bitcount")
		dl -> get_disk_pools_bitcounts(&t, &v, &n);
	else
	{
		dolog(LOG_INFO, "%s is an unknown graph-type", type.c_str());
		return NULL;
	}

	char *img_data = NULL;
	size_t img_data_len = 0;
	g -> do_draw(width, height, title, t, v, n, &img_data, &img_data_len);

	free(t);
	free(v);

	return new http_bundle(reply_headers, (unsigned char *)img_data, (int)img_data_len);
}
