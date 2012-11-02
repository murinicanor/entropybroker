#include "http_server.h"
#include "web_server.h"

web_server::web_server(std::string listen_adapter, int listen_port) : fd(-1)
{
	// FIXME
}

web_server::~web_server()
{
	if (fd != -1)
		close(fd);
}

http_file * web_server::lookup_url(std::string url)
{
	std::map<std::string, http_file *>::iterator index = objects.find(url);

	if (index != objects.end())
		return index -> second;

	return NULL;
}

void web_server::process_request(int fd)
{
	http_server hs(fd);

	// get url
	// get request type
	// get request_details
	// lookup_url -> file
	// http_bundle *response = file -> do_request(request_type, request_details);
	// hs.send_response(response);
	// delete response;
	// delete request_details;
}
