#include <errno.h>
#include <map>
#include <pthread.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <sys/socket.h>
#include <sys/types.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "request_t.h"
#include "http_bundle.h"
#include "http_file.h"
#include "http_server.h"
#include "web_server.h"

void *start_web_server_thread_wrapper(void *p)
{
	web_server *ws = reinterpret_cast<web_server *>(p);

	ws -> run();

	return NULL;
}

void start_web_server(std::string listen_adapter, int listen_port)
{
	web_server *ws = new web_server(listen_adapter, listen_port);

	pthread_t thread;
	pthread_check(pthread_create(&thread, NULL, start_web_server_thread_wrapper, ws), "pthread_create");
}

web_server::web_server(std::string listen_adapter, int listen_port)
{
	fd = start_listen(listen_adapter.c_str(), listen_port, 64);
}

web_server::~web_server()
{
	if (fd != -1)
		close(fd);
}

void * thread_wrapper_http_server(void *thread_data)
{
	int fd = *reinterpret_cast<int *>(thread_data);

	http_server *hs = new http_server(fd);

	// get url
	// get request type
	// get request_details
	// lookup_url -> file
	// http_bundle *response = file -> do_request(request_type, request_details);
	// hs.send_response(response);
	// delete response;
	// delete request_details;

	delete hs;

	close(fd);

	free(thread_data);

	return NULL;
}

void web_server::run(void)
{
	for(;;)
	{
		int *client_fd = reinterpret_cast<int *>(malloc(sizeof(int)));

		*client_fd = accept(fd, NULL, NULL);

		if (*client_fd == -1)
		{
			dolog(LOG_INFO, "web_server: accept failed: %s", strerror(errno));

			continue;
		}

		std::string host = get_endpoint_name(*client_fd);

		dolog(LOG_INFO, "web_server: connected with %s", host.c_str());

		pthread_check(pthread_create(thread, NULL, thread_wrapper_http_server, reinterpret_cast<void *>(client_fd)), "pthread_create");
	}
}

http_file * web_server::lookup_url(std::string url)
{
	std::map<std::string, http_file *>::iterator index = objects.find(url);

	if (index != objects.end())
		return index -> second;

	return NULL;
}
