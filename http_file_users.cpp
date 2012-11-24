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
		int cnt = 0;
		int msg_cnt = 0, disconnects = 0, times_empty = 0, times_full = 0, times_quota = 0, submit_while_full = 0, network_error = 0, protocol_error = 0, misc_errors = 0;
		long long int total_bits_recv = 0, total_bits_recv_in = 0, total_bits_sents = 0;
		int n_reqs = 0, n_sents = 0;
		double since_ts = now + 10000.0; // min if != 0
		double msg_ts = 0, /* max */ put_msg_ts = 0, /* max */ get_msg_ts = 0, /* max */ sent_avg = 0, sent_sd = 0, recv_avg = 0, recv_sd = 0, recv_in_avg = 0, recv_in_sd = 0;

		my_mutex_lock(clients_mutex);

		for(unsigned int index=0; index<clients -> size(); index++)
		{
			client_t *cur = clients -> at(index);

			if (cur -> username != uit -> second.username)
				continue;

			// sum stats from cur -> stats_user -> ...
			statistics *pcs = cur -> stats_user;

			cnt++;

			msg_cnt += pcs -> get_msg_cnt();
			disconnects += pcs -> get_disconnects();
			times_empty += pcs -> get_times_empty();
			times_full +=  pcs -> get_times_full();
			times_quota += pcs -> get_times_quota();
			submit_while_full += pcs -> get_submit_while_full();
			network_error += pcs -> get_network_error();
			protocol_error += pcs -> get_protocol_error();
			misc_errors += pcs -> get_misc_errors();

			long long int total = -1, total_in = -1;
			int n = -1;
			pcs -> get_recvs(&total, &n, &total_in);
			total_bits_recv += total;
			n_reqs += n;
			total_bits_recv_in += total_in;

			pcs -> get_sents(&total, &n);
			total_bits_sents += total;
			n_sents += n;

			double cur_since_ts = pcs -> get_since_ts(); // min if != 0
			if (cur_since_ts != 0 && cur_since_ts < since_ts)
				since_ts = cur_since_ts;
			msg_ts = mymax(msg_ts, pcs -> get_last_msg_ts()); // max
			put_msg_ts = mymax(put_msg_ts, pcs -> get_last_put_msg_ts()); // max
			get_msg_ts = mymax(get_msg_ts, pcs -> get_last_get_msg_ts()); // max

			double avg, sd;
			pcs -> get_sent_avg_sd(&avg, &sd);
			sent_avg += avg;
			sent_sd += sd;
			pcs -> get_recv_avg_sd(&avg, &sd);
			recv_avg += avg;
			recv_sd = sd;
			pcs -> get_recv_in_avg_sd(&avg, &sd);
			recv_in_avg += avg;
			recv_in_sd += avg;
		}

		double dcnt = double(cnt);
		sent_avg /= dcnt;
		sent_sd /= dcnt;
		recv_avg /= dcnt;
		recv_sd /= dcnt;
		recv_in_avg /= dcnt;
		recv_in_sd /= dcnt;

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
		content += time_to_str((time_t)msg_ts);
		content += "</td><td colspan=\"2\">";
		content += time_to_str((time_t)put_msg_ts);
		content += "</td><td colspan=\"2\">";
		content += time_to_str((time_t)get_msg_ts);
		content += "</td><td></td></tr>\n";
		// row 3
		content += "<tr><td>";
		content += format("%d", msg_cnt);
		content += "</td><td>";
		content += format("%d", disconnects);
		content += "</td><td>";
		content += format("%d", times_empty);
		content += "</td><td>";
		content += format("%d", times_full);
		content += "</td><td>";
		content += format("%d", times_quota);
		content += "</td><td>";
		content += format("%d", submit_while_full);
		content += "</td><td" + std::string(network_error > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", network_error);
		content += "</td><td" + std::string(protocol_error > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", protocol_error);
		content += "</td><td" + std::string(misc_errors > 0 ? " class=\"darkyellow\"" : "") + ">";
		content += format("%d", misc_errors);
		content += "</td></tr>\n";

		my_mutex_unlock(clients_mutex);

		content += "</td></tr>\n";
	}

	content += "</table>\n";

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
