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

	std::string content = "<HTML><HEAD><link rel=\"stylesheet\" type=\"text/css\" media=\"screen\" href=\"stylesheet.css\"/></HEAD><BODY>\n";
	content += "<TABLE>\n";
	content += "<TR><TH>user</TH><TH>host</TH><TH>type</TH><TH>is server</TH><TH>connected since</TH><TH>bits sent</TH><TH>bits recv</TH></TR>\n";

	for(unsigned int index=0; index<clients -> size(); index++)
	{
		client_t *p = clients -> at(index);

		content += "<TR><TD>";
		content += p -> username;
		content += "</TD><TD>";
		content += p -> host;
		content += "</TD><TD>";
		content += p -> type;
		content += "</TD><TD>";
		content += p -> is_server ? "yes" : "no";
		content += "</TD><TD>";

		time_t t = (time_t)p -> connected_since;
		struct tm *tm = localtime(&t);
		char time_buffer[128];
		strftime(time_buffer, sizeof time_buffer, "%a, %d %b %y %T %z", tm);
		content += time_buffer;

		content += "</TD><TD>";
		content += format("%d", p -> bits_sent);
		content += "</TD><TD>";
		content += format("%d", p -> bits_recv);
		content += "</TD></TR>\n";
	}

	content += "</TABLE>\n";
	content += "</BODY></HTML>\n";

	return new http_bundle(reply_headers, content.c_str());
}
