#include <map>
#include <string>
#include <time.h>
#include <vector>

#include "defines.h"
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
#include "http_file_users.h"

http_file_users::http_file_users(std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in, users *pusers_in) : clients(clients_in), clients_mutex(clients_mutex_in), pusers(pusers_in)
{
}

http_file_users::~http_file_users()
{
}

std::string http_file_users::get_url()
{
	return "/users.html";
}

std::string http_file_users::get_meta_type()
{
	return "text/html";
}

http_bundle * http_file_users::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	std::map<std::string, std::string> request_parameters = split_parameters(request_url);

	std::vector<std::string> reply_headers;

	std::string content = get_style_header();

	double now = get_ts();

	std::map<std::string, user_t> user_map = pusers -> get_usermap();

	content += "<table class=\"table2 fullwidth\">\n";
	content += "<tr class=\"lighttable\"><td>user</td><td>bits put</td><td>bits put raw</td><td>bits sent</td><td colspan=\"5\"></td></tr>\n";
	content += "<tr class=\"lighttable\"><td colspan=\"2\">latest logon</td><td colspan=\"2\">last message</td><td colspan=\"2\">last put</td><td colspan=\"2\">last get</td><td></td></tr>\n";
	content += "<tr class=\"lighttable\"><td>msgs</td><td>disconnects</td><td>empty</td><td>full</td><td>quota reached</td><td>submit while full</td><td>network error</td><td>protocol error</td><td>misc error</td></tr>\n";

	std::map<std::string, user_t>::iterator uit = user_map.begin();
	for(; uit != user_map.end(); uit++)
	{
		statistics *s = uit -> second.stats_user();

		// ** emit
		// row 1
		content += "<tr class=\"lighttable3\"><td class=\"lighttable4\">";
		content += uit -> second.username;
		content += "</td><td>";
		content += format("%lld", total_bits_recv);
		content += "</td><td>";
		content += format("%lld", total_bits_recv_in);
		content += "</td><td>";
		content += format("%lld", total_bits_sents);
		content += "</td><td colspan=\"5\"></td></tr>\n";
		// row 2
		content += "<tr class=\"lighttable2\"><td colspan=\"2\">";
		content += time_to_str((time_t)since_ts);
		content += "</td><td colspan=\"2\">";
		content += time_to_str((time_t)s -> get_msg_ts);
		content += "</td><td colspan=\"2\">";
		content += time_to_str((time_t)s -> get_put_msg_ts);
		content += "</td><td colspan=\"2\">";
		content += time_to_str((time_t)s -> get_get_msg_ts);
		content += "</td><td></td></tr>\n";
		// row 3
		content += "<tr><td>";
		content += format("%d", msg_cnt);
		content += "</td><td" + std::string(disconnects > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", disconnects);
		content += "</td><td" + std::string(times_empty > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", times_empty);
		content += "</td><td" + std::string(times_full > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", times_full);
		content += "</td><td" + std::string(times_quota > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", times_quota);
		content += "</td><td" + std::string(submit_while_full > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", submit_while_full);
		content += "</td><td" + std::string(network_error > 0 ? " class=\"darkred\"" : "") + ">";
		content += format("%d", network_error);
		content += "</td><td" + std::string(protocol_error > 0 ? " class=\"darkred\"" : "") + ">";
		content += format("%d", protocol_error);
		content += "</td><td" + std::string(misc_errors > 0 ? " class=\"darkred\"" : "") + ">";
		content += format("%d", misc_errors);
		content += "</td></tr>\n";

		my_mutex_unlock(clients_mutex);

		content += "</td></tr>\n";
	}

	content += "</table>\n";

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
