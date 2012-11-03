#include <stdlib.h>
#include <string>
#include <string.h>
#include <vector>

#include "http_bundle.h"

http_bundle::http_bundle(std::vector<std::string> headers_in, unsigned char *data_in, int data_len_in)
{
	headers = headers_in;

	if (data_in)
	{
		data = reinterpret_cast<unsigned char *>(malloc(data_len_in));
		memcpy(data, data_in, data_len_in);

		data_len = data_len_in;
	}
}

http_bundle::http_bundle(std::vector<std::string> headers_in, char *data_in)
{
	headers = headers_in;

	data = reinterpret_cast<unsigned char *>(strdup(data_in));
	data_len = strlen(data_in);
}

http_bundle::~http_bundle()
{
	free(data);
}

std::vector<std::string> http_bundle::get_headers()
{
	return headers;
}

int http_bundle::get_data_len()
{
	return data_len;
}

unsigned char *http_bundle::get_data()
{
	return data;
}
