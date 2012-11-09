void start_web_server(std::string listen_interface, int listen_port, std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex);

class web_server
{
private:
	int fd;
	std::map<std::string, http_file *> objects;
	pthread_t thread;
	std::vector<client_t *> *clients;
	pthread_mutex_t *clients_mutex;

	void add_object(http_file *p);

public:
	web_server(std::string listen_interface, int listen_port, std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex);
	~web_server();

	http_file * lookup_url(std::string url);

	void run();
};
