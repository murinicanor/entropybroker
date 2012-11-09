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

http_bundle * http_file_stats::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	std::map<std::string, std::string> request_parameters = split_parameters(request_url);
	std::map<std::string, std::string>::iterator it = request_parameters.find("id");
	long int id = -1;
	if (it != request_parameters.end())
		id = atoll(it -> second.c_str());

	std::vector<std::string> reply_headers;

	std::string content = "<HTML><HEAD><link rel=\"stylesheet\" type=\"text/css\" media=\"screen\" href=\"stylesheet.css\"/></HEAD><BODY>\n";

	if (id > 0)
	{
		my_mutex_lock(clients_mutex);

		client_t *p = find_client_by_id(clients, id);
		if (!p)
			content += format("%lld is an unknown client id", id);
		else
		{
			content += "<TABLE>\n";
			content += std::string("<TR><TD>username:</TD><TD>") + p -> username + "</TD></TR>\n";
			content += std::string("<TR><TD>host:</TD><TD>") + p -> host + "</TD></TR>\n";
			content += std::string("<TR><TD>type:</TD><TD>") + p -> type + "</TD></TR>\n";
			content += std::string("<TR><TD>is server:</TD><TD>") + (p -> is_server ? "yes" : "no") + "</TD></TR>\n";

			content += "<TR><TD>connected since:</TD><TD>" + time_to_str((time_t)p -> connected_since) + "</TD></TR>\n";
			content += "<TR><TD>last message:</TD><TD>" + time_to_str((time_t)p -> last_message) + "</TD></TR>\n";
			content += "<TR><TD>last put message:</TD><TD>" + time_to_str((time_t)p -> last_put_message) + "</TD></TR>\n";

			my_mutex_lock(&p -> stats_lck);
			content += format("<TR><TD>bits sent:</TD><TD>%d</TD></TR>\n", p -> bits_sent);
			content += format("<TR><TD>bits recv:</TD><TD>%d</TD></TR>\n", p -> bits_recv);
			my_mutex_unlock(&p -> stats_lck);

			content += std::string("<TR><TD>FIPS140 stats:</TD><TD>") + p -> pfips140 -> stats() + "</TD></TR>\n";
			content += std::string("<TR><TD>SCC stats:</TD><TD>") + p -> pscc -> stats() + "</TD></TR>\n";

			content += "</TABLE>\n";
		}

		my_mutex_unlock(clients_mutex);
	}
	else
	{
		content += "<TABLE>\n";
		content += "<TR><TH>user</TH><TH>host</TH><TH>type</TH><TH>is server</TH><TH>connected since</TH><TH>bits sent</TH><TH>bits recv</TH></TR>\n";

		my_mutex_lock(clients_mutex);
		for(unsigned int index=0; index<clients -> size(); index++)
		{
			client_t *p = clients -> at(index);

			content += "<TR><TD>";
			content += p -> username;
			content += "</TD><TD><A HREF=\"stats.html?id=";
			content += format("%d", p -> id);
			content += "\">";
			content += p -> host;
			content += "</A></TD><TD>";
			content += p -> type;
			content += "</TD><TD>";
			content += p -> is_server ? "yes" : "no";
			content += "</TD><TD>";

			content += time_to_str((time_t)p -> connected_since);

			content += "</TD><TD>";
			my_mutex_lock(&p -> stats_lck);
			content += format("%d", p -> bits_sent);
			content += "</TD><TD>";
			content += format("%d", p -> bits_recv);
			my_mutex_unlock(&p -> stats_lck);
			content += "</TD></TR>\n";
		}
		my_mutex_unlock(clients_mutex);

		content += "</TABLE>\n";
	}

	content += "</BODY></HTML>\n";

	return new http_bundle(reply_headers, content.c_str());
}
