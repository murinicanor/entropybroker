#include <errno.h>
#include <gd.h>
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
#include "data_store_int.h"
#include "data_logger.h"
#include "graph.h"
#include "http_request_t.h"
#include "http_bundle.h"
#include "http_file.h"
#include "http_file_file.h"
#include "http_file_root.h"
#include "http_file_stats.h"
#include "http_file_404.h"
#include "http_file_version.h"
#include "http_file_graph_data_logger.h"
#include "http_file_logfile.h"
#include "http_file_users.h"
#include "http_server.h"
#include "web_server.h"

typedef struct
{
	web_server *p_server;
	int fd;
} http_client_t;

void *start_web_server_thread_wrapper(void *p)
{
	web_server *ws = reinterpret_cast<web_server *>(p);

	ws -> run();

	return NULL;
}

void start_web_server(config_t *config, std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex, pools *ppools, statistics *ps, fips140 *pfips140, scc *pscc, data_logger *dl, users *pusers)
{
	web_server *ws = new web_server(config, clients, clients_mutex, ppools, ps, pfips140, pscc, dl, pusers);

	pthread_attr_t attr;
	pthread_check(pthread_attr_init(&attr), "pthread_attr_init");
	pthread_check(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED), "pthread_attr_setdetachstate");

	pthread_t thread;
	pthread_check(pthread_create(&thread, &attr, start_web_server_thread_wrapper, ws), "pthread_create");
}

web_server::web_server(config_t *config, std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex, pools *ppools, statistics *ps, fips140 *pfips140, scc *pscc, data_logger *dl, users *pusers)
{
	fd = start_listen(config -> webserver_interface.c_str(), config -> webserver_port, config -> listen_queue_size);

	add_object(new http_file_root());
	add_object(new http_file_404());
	add_object(new http_file_stats(clients, clients_mutex, ppools, ps, pfips140, pscc));
	add_object(new http_file_version());
	add_object(new http_file_file("/stylesheet.css", "text/css", WEB_DIR "/stylesheet.css"));
	add_object(new http_file_file("/favicon.ico", "image/x-ico", WEB_DIR "/favicon.ico"));
	add_object(new http_file_file("/logo.png", "image/png", WEB_DIR "/logo.png"));
	add_object(new http_file_graph_data_logger(dl, config -> graph_font));
	add_object(new http_file_logfile(ps));
	add_object(new http_file_file("/logo-bw.png", "image/png", WEB_DIR "/logo-bw.png"));
	add_object(new http_file_file("/logfiles.png", "image/png", WEB_DIR "/logfiles.png"));
	add_object(new http_file_file("/statistics.png", "image/png", WEB_DIR "/statistics.png"));
	add_object(new http_file_users(clients, clients_mutex, pusers));
	add_object(new http_file_file("/users.png", "image/png", WEB_DIR "/users.png"));
}

web_server::~web_server()
{
	if (fd != -1)
		close(fd);

	std::map<std::string, http_file *>::iterator it = objects.begin();
	while(it != objects.end())
	{
		delete it -> second;
		it++;
	}
}

void web_server::add_object(http_file *p)
{
	objects.insert(std::pair<std::string, http_file *>(p -> get_url(), p));
}

void * thread_wrapper_http_server(void *thread_data)
{
	http_client_t *p_data = reinterpret_cast<http_client_t *>(thread_data);

	http_server *hs = new http_server(p_data -> fd);

	// get url
	std::string url = hs -> get_request_url();
	dolog(LOG_INFO, "Processing url: %s", url.c_str());

	// get request type
	http_request_t request_type = hs -> get_request_type();

	// get request_details
	http_bundle *request_details = hs -> get_request();

	// lookup_url -> file
	http_file *obj = p_data -> p_server -> lookup_url(url); // not allocated, don't free it
	if (!obj)
	{
		dolog(LOG_INFO, "URL not found");
		obj = p_data -> p_server -> lookup_url("/404.html"); // not allocated, don't free it
	}

	if (!obj)
		dolog(LOG_INFO, "No object applicable found");
	else
	{
		http_bundle *response = obj -> do_request(request_type, url, request_details);

		std::vector<std::string> headers;
		headers.push_back(("Content-Type: " + obj -> get_meta_type()).c_str());
		headers.push_back("Connection: close");

		hs -> send_response(200, &headers, response);

		delete response;
	}

	delete request_details;

	delete hs;

	close(p_data -> fd);

	delete p_data;

	return NULL;
}

void web_server::run(void)
{
	pthread_attr_t attr;

	pthread_check(pthread_attr_init(&attr), "pthread_attr_init");
	pthread_check(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED), "pthread_attr_setdetachstate");

	for(;;)
	{
		int client_fd = accept(fd, NULL, NULL);

		if (client_fd == -1)
		{
			dolog(LOG_INFO, "web_server: accept failed: %s", strerror(errno));

			continue;
		}

		std::string host = get_endpoint_name(client_fd);

		dolog(LOG_INFO, "web_server: connected with %s", host.c_str());

		http_client_t *p_client = new http_client_t;
		p_client -> p_server = this;
		p_client -> fd = client_fd;

		pthread_t thread;
		pthread_check(pthread_create(&thread, &attr, thread_wrapper_http_server, reinterpret_cast<void *>(p_client)), "pthread_create");
	}
}

http_file * web_server::lookup_url(std::string url)
{
	size_t parameters_pos = url.find('?');
	if (parameters_pos != std::string::npos)
		url = url.substr(0, parameters_pos);

	std::map<std::string, http_file *>::iterator index = objects.find(url);

	if (index != objects.end())
		return index -> second;

	return NULL;
}
