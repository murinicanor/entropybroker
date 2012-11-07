#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>

#include "log.h"
#include "http_bundle.h"
#include "http_request_t.h"
#include "http_file.h"
#include "http_file_file.h"

http_file_file::http_file_file(std::string url_in, std::string meta_in, std::string file_in) : url(url_in), meta(meta_in), file(file_in)
{
}

http_file_file::~http_file_file()
{
}

std::string http_file_file::get_url()
{
	return url;
}

std::string http_file_file::get_meta_type()
{
	return meta;
}

void http_file_file::load_file(unsigned char **p, int *len)
{
	bool ok = true;
	struct stat st;

	for(;;)
	{
		if (stat(file.c_str(), &st) == -1)
		{
			dolog(LOG_INFO, "stat on %s failed: %s", file.c_str(), strerror(errno));
			ok = false;
			break;
		}

		FILE *fh = fopen(file.c_str(), "rb");
		if (!fh)
		{
			ok = false;
			break;
		}

		*p = (unsigned char *)malloc(st.st_size);
		if (!*p)
		{
			ok = false;
			fclose(fh);
			break;
		}

		if (fread(*p, st.st_size, 1, fh) != st.st_size)
		{
			dolog(LOG_INFO, "short read on %s", file.c_str());
			ok = false;
			fclose(fh);
			free(*p);
			break;
		}

		fclose(fh);

		break;
	}

	if (!ok)
	{
		*p = (unsigned char *)strdup("file not found");
		*len = strlen((char *)*p);
	}
}

http_bundle * http_file_file::do_request(http_request_t request_type, http_bundle *request_details)
{
	unsigned char *data = NULL;
	int data_len = 0;

	load_file(&data, &data_len);

	std::vector<std::string> reply_headers;

	http_bundle *result = new http_bundle(reply_headers, data, data_len);

	free(data);

	return result;
}
