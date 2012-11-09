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

        unsigned int parameters_pos = url.find('?');
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
	}

	return parameters;
}

http_bundle * http_file::do_request(http_request_t request_type, std::string request_url, http_bundle *request_details)
{
	return NULL;
}
