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
	content += "<tr class=\"lighttable\"><td>user</td><td>bits recv</td><td>bits sent</td><td>errors</td><td>warnings</td>...</tr>\n";

	std::map<std::string, user_t>::iterator uit = user_map.begin();
	for(; uit != user_map.end(); uit++)
	{
		content += "<tr><td>";
		content += uit -> second.username;
		content += "</td><td>";

		my_mutex_lock(clients_mutex);

		for(unsigned int index=0; index<clients -> size(); index++)
		{
			client_t *cur = clients -> at(index);

			if (cur -> username != uit -> second.username)
				continue;

			// sum stats from cur -> stats_user -> ...
			// emit
/*
	int get_reset_bps_cur();
	int get_msg_cnt();
	int get_disconnects();
	int get_times_empty();
	int get_times_full();
	int get_times_quota();
	int get_submit_while_full();
	int get_network_error();
	int get_protocol_error();
	int get_misc_errors();
	void get_recvs(long long int *total_bits, int *n_reqs, long long int *total_bits_in);
	void get_sents(long long int *total_bits, int *n_sents);
	double get_since_ts(); // min if != 0
	double get_last_msg_ts(); // max
	double get_last_put_msg_ts(); // max
	double get_last_get_msg_ts(); // max
	void get_sent_avg_sd(double *avg, double *sd);
	void get_recv_avg_sd(double *avg, double *sd);
	void get_recv_in_avg_sd(double *avg, double *sd);
*/

		}

		my_mutex_unlock(clients_mutex);

		content += "</td></tr>\n";
	}

	content += "</table>\n";

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
