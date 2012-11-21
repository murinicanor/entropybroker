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
#include "http_file_logfile.h"

http_file_logfile::http_file_logfile(statistics *ps_in) : ps(ps_in)
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

	std::vector<history_logins> log = ps -> get_login_history();

	std::string content = get_style_header();

	content += "<TABLE CLASS=\"table2\" WIDTH=100%>\n";
	content += "<TR CLASS=\"lighttable\"><TD>event type</TD><TD>user</TD><TD>host</TD><TD>type</TD><TD>connected since</TD><TD>duration</TD><TD>notes</TD></TR>\n";

	for(int index=log.size()-1; index >= 0; index--)
	{
		content += "<TR><TD>";

		switch(log.at(index).hl)
		{
			case HL_LOGIN_OK:
				content += "login ok";
				break;
			case HL_LOGOUT_OK:
				content += "logout ok";
				break;
			case HL_LOGIN_USER_FAIL:
				content += "unknown user";
				break;
			case HL_LOGIN_PW_FAIL:
				content += "password fail";
				break;
			case HL_LOGIN_OTHER:
				content += "other error";
				break;
			default:
				content += "INTERNAL ERROR";
		}

		content += "</TD><TD>" + log.at(index).user + "</TD>";
		content += "<TD>" + log.at(index).host + "</TD>";
		content += "<TD>" + log.at(index).type + "</TD>";
		content += "<TD>" + time_to_str((time_t)log.at(index).time_logged_in) + "</TD>";
		if (log.at(index).hl == HL_LOGOUT_OK)
			content += format("<TD>%f</TD>", log.at(index).duration);
		else
			content += "<TD></TD>";
		content += "<TD>" + log.at(index).details + "</TD>";
		content += "</TR>";
	}
	content += "</TABLE>\n";

	content += get_style_tail();

	return new http_bundle(reply_headers, content.c_str());
}
