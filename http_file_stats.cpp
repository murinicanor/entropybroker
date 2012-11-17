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

			content += "<TABLE CLASS=\"table2\" WIDTH=100%>\n";
			content += std::string("<TR><TD WIDTH=200>username:</TD><TD>") + p -> username + "</TD></TR>\n";
			content += std::string("<TR><TD>host:</TD><TD>") + p -> host + "</TD></TR>\n";
			content += std::string("<TR><TD>type:</TD><TD>") + p -> type + "</TD></TR>\n";
			content += std::string("<TR><TD>is server:</TD><TD>") + (p -> is_server ? "yes" : "no") + "</TD></TR>\n";

			content += "<TR><TD>connected since:</TD><TD>" + time_to_str((time_t)pcs -> get_since_ts()) + "</TD></TR>\n";
			content += format("<TR><TD>duration:</TD><TD>%fs</TD></TR>\n", now - pcs -> get_since_ts());
			content += format("<TR><TD>avg time between msgs:</TD><TD>%fs</TD></TR>\n", (now - pcs -> get_since_ts()) / double(pcs -> get_msg_cnt()));
			content += "<TR><TD>last message:</TD><TD>" + time_to_str((time_t)pcs -> get_last_msg_ts()) + "</TD></TR>\n";
			content += "<TR><TD>last put message:</TD><TD>" + time_to_str((time_t)pcs -> get_last_put_msg_ts()) + "</TD></TR>\n";

			content += format("<TR><TD>not allowed:</TD><TD>%d</TD></TR>\n", pcs -> get_times_not_allowed());
			content += format("<TR><TD>quota:</TD><TD>%d</TD></TR>\n", pcs -> get_times_quota());
			content += format("<TR><TD>pools empty:</TD><TD>%d</TD></TR>\n", pcs -> get_times_empty());
			content += format("<TR><TD>full:</TD><TD>%d</TD></TR>\n", pcs -> get_times_full());

			long long int total_bits_recv = 0, total_bits_recv_in = 0;
			int n_recv = 0;
			pcs -> get_recvs(&total_bits_recv, &n_recv, &total_bits_recv_in);
			content += format("<TR><TD>put requests:</TD><TD>%d</TD></TR>\n", n_recv);
			content += format("<TR><TD>bits put:</TD><TD>%lld</TD></TR>\n", total_bits_recv);
			content += format("<TR><TD>bits put density:</TD><TD>%f%%</TD></TR>\n", double(total_bits_recv * 100) / double(total_bits_recv_in));
			content += format("<TR><TD>avg bits/put:</TD><TD>%f</TD></TR>\n", double(total_bits_recv) / double(n_recv));
			content += format("<TR><TD>put bps:</TD><TD>%f</TD></TR>\n", double(total_bits_recv) / (now - pcs -> get_since_ts()));

			long long int total_bits_sent = 0;
			int n_sent = 0;
			pcs -> get_sents(&total_bits_sent, &n_sent);
			content += format("<TR><TD>get requests:</TD><TD>%d</TD></TR>\n", n_sent);
			content += format("<TR><TD>bits requested:</TD><TD>%lld</TD></TR>\n", total_bits_sent);
			content += format("<TR><TD>avg bits/get:</TD><TD>%f</TD></TR>\n", double(total_bits_sent) / double(n_sent));
			content += format("<TR><TD>get bps:</TD><TD>%f</TD></TR>\n", double(total_bits_sent) / (now - pcs -> get_since_ts()));

			my_mutex_lock(&p -> stats_lck);
			content += std::string("<TR><TD>FIPS140 stats:</TD><TD>") + p -> pfips140 -> stats() + "</TD></TR>\n";
			content += std::string("<TR><TD>SCC stats:</TD><TD>") + p -> pscc -> stats() + "</TD></TR>\n";
			my_mutex_unlock(&p -> stats_lck);

			content += "</TABLE>\n";
		}

		my_mutex_unlock(clients_mutex);
	}
	else
	{
		// PER USER STATS
		content += "<TABLE CLASS=\"table2\" WIDTH=100%>\n";
		content += "<TR CLASS=\"lighttable\"><TD>user</TD><TD>host</TD><TD>type</TD><TD>is server</TD><TD>connected since</TD><TD>bits recv</TD><TD>bits sent</TD></TR>\n";

		double recv_bps = 0, sent_bps = 0;
		int n_server = 0, n_client = 0;

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

			statistics *pcs = p -> stats_user;

			content += time_to_str((time_t)pcs -> get_since_ts());
			double duration = now - pcs -> get_since_ts();

			long long int total_bits_recv = 0, total_bits_recv_in = 0, total_bits_sent = 0;
			int n_recv = 0, n_sent = 0;
			pcs -> get_recvs(&total_bits_recv, &n_recv, &total_bits_recv_in);
			pcs -> get_sents(&total_bits_sent, &n_sent);
			content += "</TD><TD>";
			content += format("%lld", total_bits_recv);
			if (p -> is_server)
			{
				recv_bps += double(total_bits_recv) / duration;
				n_server++;
			}
			else
			{
				sent_bps += double(total_bits_sent) / duration;
				n_client++;
			}
			content += "</TD><TD>";
			content += format("%lld", total_bits_sent);
			content += "</TD></TR>\n";
		}
		my_mutex_unlock(clients_mutex);
		content += format("<TR CLASS=\"lighttable\"><TD COLSPAN=\"4\"></TD><TD ALIGN=\"right\">bps:</TD><TD>%.1f</TD><TD>%.1f</TD></TR>\n", sent_bps / double(n_server), recv_bps / double(n_client));

		content += "</TABLE>\n";
		content += format("Number of connected clients/servers: %d<BR>\n", clients -> size());
		content += "<BR>\n";

		// GLOBAL STATS
		content += "<TABLE CLASS=\"table2\" WIDTH=100%>\n";
		content += "<TR><TD WIDTH=200>running since:</TD><TD>" + time_to_str((time_t)ps -> get_start_ts()) + "</TD></TR>\n";
		content += format("<TR><TD>duration:</TD><TD>%fs</TD></TR>\n", now - ps -> get_start_ts());
		content += "<TR><TD>first msg:</TD><TD>" + time_to_str((time_t)ps -> get_since_ts()) + "</TD></TR>\n";
		content += format("<TR><TD>avg time between msgs:</TD><TD>%fs</TD></TR>\n", (now - ps -> get_since_ts()) / double(ps -> get_msg_cnt()));
		content += "<TR><TD>last message:</TD><TD>" + time_to_str((time_t)ps -> get_last_msg_ts()) + "</TD></TR>\n";
		content += "<TR><TD>last put message:</TD><TD>" + time_to_str((time_t)ps -> get_last_put_msg_ts()) + "</TD></TR>\n";

		content += format("<TR><TD>not allowed:</TD><TD>%d</TD></TR>\n", ps -> get_times_not_allowed());
		content += format("<TR><TD>quota:</TD><TD>%d</TD></TR>\n", ps -> get_times_quota());
		content += format("<TR><TD>pools empty:</TD><TD>%d</TD></TR>\n", ps -> get_times_empty());
		content += format("<TR><TD>full:</TD><TD>%d</TD></TR>\n", ps -> get_times_full());

		long long int total_bits_recv = 0, total_bits_recv_in = 0;
		int n_recv = 0;
		ps -> get_recvs(&total_bits_recv, &n_recv, &total_bits_recv_in);
		content += format("<TR><TD>put requests:</TD><TD>%d</TD></TR>\n", n_recv);
		content += format("<TR><TD>bits put:</TD><TD>%lld</TD></TR>\n", total_bits_recv);
		// FIXME should be get density content += format("<TR><TD>bits put density:</TD><TD>%f%%</TD></TR>\n", double(total_bits_recv * 100) / double(total_bits_recv_in));
		content += format("<TR><TD>avg bits/put:</TD><TD>%f</TD></TR>\n", double(total_bits_recv) / double(n_recv));
		content += format("<TR><TD>put bps:</TD><TD>%f</TD></TR>\n", double(total_bits_recv) / (now - ps -> get_since_ts()));

		long long int total_bits_sent = 0;
		int n_sent = 0;
		ps -> get_sents(&total_bits_sent, &n_sent);
		content += format("<TR><TD>get requests:</TD><TD>%d</TD></TR>\n", n_sent);
		content += format("<TR><TD>bits requested:</TD><TD>%lld</TD></TR>\n", total_bits_sent);
		content += format("<TR><TD>avg bits/get:</TD><TD>%f</TD></TR>\n", double(total_bits_sent) / double(n_sent));
		content += format("<TR><TD>get bps:</TD><TD>%f</TD></TR>\n", double(total_bits_sent) / (now - ps -> get_since_ts()));

		content += std::string("<TR><TD>FIPS140 stats:</TD><TD>") + pfips140 -> stats() + "</TD></TR>\n";
		content += std::string("<TR><TD>SCC stats:</TD><TD>") + pscc -> stats() + "</TD></TR>\n";

		content += "</TABLE>\n";
		content += "<BR>\n";

		// POOL STATS
		content += "<TABLE CLASS=\"table2\" WIDTH=100%>\n";
		int bit_sum = ppools -> get_bit_sum(1.0);
		content += format("<TR><TD WIDTH=200>in memory bit count:</TD><TD>%d</TD></TR>\n", bit_sum);
		int mem_pools = ppools -> get_memory_pool_count();
		content += format("<TR><TD>pools in memory:</TD><TD>%d</TD></TR>\n", mem_pools);
		content += format("<TR><TD>avg bits/mem pool:</TD><TD>%f (def max: %d)</TD></TR>\n", double(bit_sum) / double(mem_pools), DEFAULT_POOL_SIZE_BITS);
		content += format("<TR><TD>pool files on disk:</TD><TD>%d</TD></TR>\n", ppools -> get_disk_pool_count());
		content += "</TABLE>\n";
		content += "<BR>\n";

		content += "<H2>number of memory pools</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=mem_pool_counts&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>number of disk pools</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=dsk_pool_counts&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>number of connections</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=connection_counts&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>memory pools bit count</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=mem_pools_bitcount&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>disk pools bit count</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=dsk_pools_bitcount&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>data from servers to broker (per interval, entropy count)</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=recv_bit_count&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>data from servers to broker (per interval, raw data)</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=recv_bit_count_in&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
		content += "<H2>data from broker to clients (per interval)</H2>\n";
		content += "<IMG SRC=\"/graph.png?type=sent_bit_count&width=640&height=240\"><BR>\n";
		content += "<BR>\n";
	}

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
