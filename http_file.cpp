#include <map>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <vector>

#include "utils.h"
#include "statistics.h"
#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"

http_file::http_file()
{
}

http_file::~http_file()
{
}

std::string http_file::get_url()
{
	return "?";
}

std::map<std::string, std::string> http_file::split_parameters(std::string url)
{
	std::map<std::string, std::string> parameters;

        size_t parameters_pos = url.find('?');
        if (parameters_pos != std::string::npos && parameters_pos < url.size() - 1)
	{
		std::string dummy = url.substr(parameters_pos + 1);

		char **par_array = NULL;
		int par_array_n = 0;
		split_string(dummy.c_str(), "&", &par_array, &par_array_n);

		for(int index=0; index<par_array_n; index++)
		{
			char *is = strchr(par_array[index], '=');
			if (!is)
				parameters.insert(std::pair<std::string, std::string>(par_array[index], ""));
			else
			{
				*is = 0x00;
				parameters.insert(std::pair<std::string, std::string>(par_array[index], is + 1));
			}

			free(par_array[index]);
		}

		free(par_array);
	}

	return parameters;
}

http_bundle * http_file::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	return NULL;
}

std::string http_file::get_style_header()
{
	return
		"<!DOCTYPE html>\n"
		"<html>\n"
		" <head>\n"
		"  <meta charset=\"utf-8\"/>\n"
		"  <title>Entropy broker</title>\n"
		"  <link rel=\"stylesheet\" media=\"screen\" href=\"stylesheet.css\">\n"
		"  <link rel=\"shortcut icon\" href=\"/favicon.ico\">\n"
		"<!--[if lt IE 9]>\n"
		"  <script>\n"
		"  (function(){\n"
		"    document.createElement('header');\n"
		"    document.createElement('section');\n"
		"    document.createElement('footer');\n"
		"    document.createElement('nav');\n"
		"  })()\n"
		"  </script>\n"
		"<![endif]-->\n"
		" </head>\n"
		" <body>\n"
		"  <header>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"140\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"93\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"62\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"41\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"27\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"18\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"12\"/>\n"
		"   <img src=\"logo.png\" alt=\"entropy broker logo\" width=\"8\"/>\n"
		"  </header>\n"
		"\n"
		"  <section class=\"content\">\n"
		"\n"
		"   <h1>Entropy Broker</h1>\n";
}

std::string http_file::get_style_tail()
{
	return
		"  </section>\n"
		"\n"
		"  <footer>\n"
		"   <a href=\"http://www.vanheusden.com/\">www.vanheusden.com</a>\n"
		"  </footer>\n"
		" </body>\n"
		"</html>\n";
}

std::string generate_logging_table(statistics *ps, std::string username)
{
	std::vector<history_logins> log = ps -> get_login_history();

	std::string content = "<table class=\"table2 tablemargins fullwidth\">\n";
	content += "<tr class=\"lighttable\"><td class=\"timestamp\">event ts</td><td>event type</td><td>user</td><td>host</td><td>type</td></tr>\n";
	content += "<tr class=\"lighttable\"><td>connected since</td><td>duration</td><td colspan=\"3\">notes</td></tr>\n";

	double now_ts = get_ts();
	for(int index=log.size()-1; index >= 0; index--)
	{
		if (username.size() > 0 && log.at(index).user != username)
			continue;

		content += "<tr>";
		content += "<td>" + time_to_str((time_t)log.at(index).event_ts) + "</td>";
		content += "<td>";

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

		content += "</td><td>" + log.at(index).user + "</td>";
		content += "<td>" + log.at(index).host + "</td>";
		content += "<td>" + log.at(index).type + "</td>";
		content += "</tr>";
		content += "<tr class=\"lighttable2\">";
		content += "<td>" + time_to_str((time_t)log.at(index).time_logged_in) + "</td>";
		if (log.at(index).hl == HL_LOGOUT_OK)
			content += format("<td>%f</td>", log.at(index).duration);
		else if (log.at(index).hl == HL_LOGIN_OK)
			content += format("<td>[%f]</td>", now_ts - log.at(index).time_logged_in);
		else
			content += "<td></td>";
		content += "<td colspan=\"3\">" + log.at(index).details + "</td>";
		content += "</tr>\n";
	}
	content += "</table>\n";

	return content;
}
