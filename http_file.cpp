#include <map>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <vector>

#include "utils.h"
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
	return "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Frameset//EN\" \"http://www.w3.org/TR/html4/frameset.dtd\"> \n"
		"<HTML><HEAD>\n"
		"<link rel=\"stylesheet\" type=\"text/css\" media=\"screen\" href=\"stylesheet.css\">\n"
		"<link rel=\"shortcut icon\" href=\"/favicon.ico\">\n"
		"<meta http-equiv=\"Content-Type\" content=\"text/html;charset=utf-8\" >\n"
		"</HEAD><BODY>\n"
		"<TABLE HEIGHT=\"100%\" WIDTH=\"100%\"><TR><TD WIDTH=\"150\" ALIGN=\"LEFT\" VALIGN=\"TOP\">\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=140><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=93><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=62><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=41><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=27><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=18><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=12><BR><BR>\n"
		"<IMG SRC=\"logo.png\" ALT=\"entropy broker logo\" WIDTH=8>\n"
		"</TD><TD VALIGN=\"TOP\">\n"
		"<BR CLASS=\"myBr\">\n"
		"<H1>Entropy Broker</H1>\n";
}

std::string http_file::get_style_tail()
{
	return "</TD></TR>\n"
		"<TR HEIGHT=\"32\"><TD ALIGN=\"RIGHT\" COLSPAN=\"3\"><A HREF=\"http://www.vanheusden.com/\">www.vanheusden.com</A></TD></TR>"
		"</TABLE>"
		"</BODY></HTML>";
}
