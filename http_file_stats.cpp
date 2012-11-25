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
#include "statistics.h"
#include "users.h"
#include "handle_client.h"
#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_stats.h"

http_file_stats::http_file_stats(std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in, pools *ppools_in, statistics *ps_in, fips140 *pfips140_in, scc *pscc_in) : clients(clients_in), clients_mutex(clients_mutex_in), ppools(ppools_in), ps(ps_in), pfips140(pfips140_in), pscc(pscc_in)
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

	std::string content = get_style_header();

	double now = get_ts();

	if (id > 0)
	{
		my_mutex_lock(clients_mutex);

		client_t *p = find_client_by_id(clients, id);
		if (!p)
			content += format("%lld is an unknown client id", id);
		else
		{
			statistics *pcs = p -> stats_user;

			content += "<table class=\"table2 fullwidth\">\n";
			content += std::string("<tr><td class=\"keys\">username:</td><td>") + p -> username + "</td></tr>\n";
			content += std::string("<tr><td>host:</td><td>") + p -> host + "</td></tr>\n";
			content += std::string("<tr><td>type:</td><td>") + p -> type + "</td></tr>\n";
			content += std::string("<tr><td>is server:</td><td>") + (p -> is_server ? "yes" : "no") + "</td></tr>\n";

			content += "<tr><td>connected since:</td><td>" + time_to_str((time_t)p -> connected_since) + "</td></tr>\n";
			content += format("<tr><td>duration:</td><td>%fs</td></tr>\n", now - p -> connected_since);
			content += format("<tr><td>avg time between msgs:</td><td>%fs</td></tr>\n", (now - p -> connected_since) / double(pcs -> get_msg_cnt()));
			content += "<tr><td>last message:</td><td>" + time_to_str((time_t)p -> last_message) + "</td></tr>\n";
			content += "<tr><td>last put message:</td><td>" + time_to_str((time_t)p -> last_put_message) + "</td></tr>\n";

			content += format("<tr><td>denied because of quota:</td><td>%d</td></tr>\n", pcs -> get_times_quota());
			content += format("<tr><td>denied because pools empty:</td><td>%d</td></tr>\n", pcs -> get_times_empty());
			content += format("<tr><td>denied because full:</td><td>%d</td></tr>\n", pcs -> get_times_full());
			content += format("<tr><td>allowed while full:</td><td>%d</td></tr>\n", pcs -> get_submit_while_full());
			content += format("<tr><td>network errors:</td><td>%d</td></tr>\n", pcs -> get_network_error());
			content += format("<tr><td>protocol errors:</td><td>%d</td></tr>\n", pcs -> get_protocol_error());
			content += format("<tr><td>miscellaneous errors:</td><td>%d</td></tr>\n", pcs -> get_misc_errors());

			long long int total_bits_recv = 0, total_bits_recv_in = 0;
			int n_recv = 0;
			pcs -> get_recvs(&total_bits_recv, &n_recv, &total_bits_recv_in);
			content += format("<tr><td>put requests:</td><td>%d</td></tr>\n", n_recv);
			content += format("<tr><td>bits put:</td><td>%lld</td></tr>\n", total_bits_recv);
			content += format("<tr><td>bits put density:</td><td>%f%%</td></tr>\n", double(total_bits_recv * 100) / double(total_bits_recv_in));
			content += format("<tr><td>avg bits/put:</td><td>%f</td></tr>\n", double(total_bits_recv) / double(n_recv));
			content += format("<tr><td>put bps:</td><td>%f</td></tr>\n", double(total_bits_recv) / (now - p -> connected_since));

			long long int total_bits_sent = 0;
			int n_sent = 0;
			pcs -> get_sents(&total_bits_sent, &n_sent);
			content += format("<tr><td>get requests:</td><td>%d</td></tr>\n", n_sent);
			content += format("<tr><td>bits requested:</td><td>%lld</td></tr>\n", total_bits_sent);
			content += format("<tr><td>avg bits/get:</td><td>%f</td></tr>\n", double(total_bits_sent) / double(n_sent));
			content += format("<tr><td>get bps:</td><td>%f</td></tr>\n", double(total_bits_sent) / (now - p -> connected_since));

			my_mutex_lock(&p -> stats_lck);
			content += std::string("<tr><td>FIPS140 stats:</td><td>") + p -> pfips140 -> stats() + "</td></tr>\n";
			content += std::string("<tr><td>SCC stats:</td><td>") + p -> pscc -> stats() + "</td></tr>\n";
			my_mutex_unlock(&p -> stats_lck);

			content += "</table>\n";
			content += "<br>\n";

			content += generate_logging_table(ps, p -> username);
		}

		my_mutex_unlock(clients_mutex);
	}
	else
	{
		// PER USER STATS
		content += "<table class=\"table2 fullwidth\">\n";
		content += "<tr class=\"lighttable\"><td>user</td><td>host</td><td class=\"timestamp\">connected since</td><td>bits recv</td><td>bits sent</td><td>errors</td><td>warnings</td></tr>\n";

		double recv_bps = 0, sent_bps = 0;

		my_mutex_lock(clients_mutex);
		for(unsigned int index=0; index<clients -> size(); index++)
		{
			client_t *p = clients -> at(index);

			content += "<tr><td>";
			content += p -> username;
			content += "</td><td><A HREF=\"stats.html?id=";
			content += format("%d", p -> id);
			content += "\">";
			content += p -> host;
			content += "</A></td><td>";

			statistics *pcs = p -> stats_user;

			content += time_to_str((time_t)p -> connected_since);
			double duration = now - p -> connected_since;

			long long int total_bits_recv = 0, total_bits_recv_in = 0, total_bits_sent = 0;
			int n_recv = 0, n_sent = 0;
			pcs -> get_recvs(&total_bits_recv, &n_recv, &total_bits_recv_in);
			pcs -> get_sents(&total_bits_sent, &n_sent);
			content += "</td><td>";
			content += format("%lld", total_bits_recv);
			if (p -> is_server)
				recv_bps += double(total_bits_recv) / duration;
			else
				sent_bps += double(total_bits_sent) / duration;
			content += "</td><td>";
			content += format("%lld", total_bits_sent);
			content += "</td><td>";
			// errors
			int errors = pcs -> get_network_error();
			errors += pcs -> get_protocol_error();
			errors += pcs -> get_misc_errors();
			content += format("%d", errors);
			content += "</td><td>";
			// warnings
			int warnings = pcs -> get_times_quota();
			warnings += pcs -> get_times_empty();
			warnings += pcs -> get_times_full();
			warnings += pcs -> get_submit_while_full();
			content += format("%d", warnings);
			content += "</td></tr>\n";
		}
		my_mutex_unlock(clients_mutex);
		content += format("<tr class=\"lighttable\"><td colspan=\"3\" class=\"alignright\">bps:&nbsp;</td><td>%.1f</td><td>%.1f</td><td colspan=\"2\"></td></tr>\n", recv_bps, sent_bps);

		content += "</table>\n";
		content += format("Number of connected clients/servers: %d<br>\n", clients -> size());
		content += "<br>\n";

		// GLOBAL STATS
		content += "<table class=\"table2 fullwidth\">\n";
		content += "<tr><td class=\"keys\">running since:</td><td>" + time_to_str((time_t)get_start_ts()) + "</td></tr>\n";
		content += format("<tr><td>duration:</td><td>%fs</td></tr>\n", now - get_start_ts());
		content += format("<tr><td>avg time between msgs:</td><td>%fs</td></tr>\n", (now - get_start_ts()) / double(ps -> get_msg_cnt()));
		content += "<tr><td>last message:</td><td>" + time_to_str((time_t)ps -> get_last_msg_ts()) + "</td></tr>\n";
		content += "<tr><td>last put message:</td><td>" + time_to_str((time_t)ps -> get_last_put_msg_ts()) + "</td></tr>\n";

		content += format("<tr><td>logged out sessions: </td><td>%d</td></tr>\n", ps -> get_disconnects());

		content += format("<tr><td>denied because of quota:</td><td>%d</td></tr>\n", ps -> get_times_quota());
		content += format("<tr><td>denied because pools empty:</td><td>%d</td></tr>\n", ps -> get_times_empty());
		content += format("<tr><td>denied because full:</td><td>%d</td></tr>\n", ps -> get_times_full());
		content += format("<tr><td>allowed while full:</td><td>%d</td></tr>\n", ps -> get_submit_while_full());
		content += format("<tr><td>network errors:</td><td>%d</td></tr>\n", ps -> get_network_error());
		content += format("<tr><td>protocol errors:</td><td>%d</td></tr>\n", ps -> get_protocol_error());
		content += format("<tr><td>miscellaneous errors:</td><td>%d</td></tr>\n", ps -> get_misc_errors());

		long long int total_bits_recv = 0, total_bits_recv_in = 0;
		int n_recv = 0;
		ps -> get_recvs(&total_bits_recv, &n_recv, &total_bits_recv_in);
		content += format("<tr><td>put requests:</td><td>%d</td></tr>\n", n_recv);
		content += format("<tr><td>bits put:</td><td>%lld</td></tr>\n", total_bits_recv);
		// FIXME should be get density content += format("<tr><td>bits put density:</td><td>%f%%</td></tr>\n", double(total_bits_recv * 100) / double(total_bits_recv_in));
		content += format("<tr><td>avg bits/put:</td><td>%f</td></tr>\n", double(total_bits_recv) / double(n_recv));
		content += format("<tr><td>put bps:</td><td>%f</td></tr>\n", double(total_bits_recv) / (now - get_start_ts()));

		long long int total_bits_sent = 0;
		int n_sent = 0;
		ps -> get_sents(&total_bits_sent, &n_sent);
		content += format("<tr><td>get requests:</td><td>%d</td></tr>\n", n_sent);
		content += format("<tr><td>bits requested:</td><td>%lld</td></tr>\n", total_bits_sent);
		content += format("<tr><td>avg bits/get:</td><td>%f</td></tr>\n", double(total_bits_sent) / double(n_sent));
		content += format("<tr><td>get bps:</td><td>%f</td></tr>\n", double(total_bits_sent) / (now - get_start_ts()));

		content += std::string("<tr><td>FIPS140 stats:</td><td>") + pfips140 -> stats() + "</td></tr>\n";
		content += std::string("<tr><td>SCC stats:</td><td>") + pscc -> stats() + "</td></tr>\n";

		content += "</table>\n";
		content += "<br>\n";

		// POOL STATS
		content += "<table class=\"table2 fullwidth\">\n";
		int bit_sum = ppools -> get_bit_sum(1.0);
		content += format("<tr><td class=\"keys\">in memory bit count:</td><td>%d</td></tr>\n", bit_sum);
		int mem_pools = ppools -> get_memory_pool_count();
		content += format("<tr><td>pools in memory:</td><td>%d</td></tr>\n", mem_pools);
		content += format("<tr><td>avg bits/mem pool:</td><td>%f (def max: %d)</td></tr>\n", double(bit_sum) / double(mem_pools), DEFAULT_POOL_SIZE_BITS);
		int disk_file_cnt = ppools -> get_disk_pool_count();
		content += format("<tr><td>pool files on disk:</td><td>%d</td></tr>\n", disk_file_cnt);
		int disk_bit_sum = ppools -> get_disk_pool_bit_count();
		content += format("<tr><td>on disk bit count:</td><td>%d</td></tr>\n", disk_bit_sum);
		content += format("<tr><td>avg bits/disk pool:</td><td>%f</td></tr>\n", double(disk_bit_sum) / double(disk_file_cnt));
		content += "</table>\n";
		content += "<br>\n";

		std::string dimensions = "&amp;width=640&amp;height=240";

		content += "<h2>number of memory pools</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=mem_pool_counts" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += "<h2>number of disk pools</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=dsk_pool_counts" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += "<h2>number of connections</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=connection_counts" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += "<h2>memory pools bit count</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=mem_pools_bitcount" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += "<h2>disk pools bit count</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=dsk_pools_bitcount" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += format("Interval: %ds\n", MEASURE_INTERVAL);
		content += "<h2>data from servers to broker (per interval, entropy count)</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=recv_bit_count" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += "<h2>data from servers to broker (per interval, raw data)</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=recv_bit_count_in" + dimensions + "\" /><br>\n";
		content += "<br>\n";
		content += "<h2>data from broker to clients (per interval)</h2>\n";
		content += "<img alt=\"graph\" src=\"/graph.png?type=sent_bit_count" + dimensions + "\" /><br>\n";
		content += "<br>\n";
	}

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
