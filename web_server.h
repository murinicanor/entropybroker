void start_web_server(std::string listen_interface, int listen_port);

class web_server
{
private:
	int fd;
	std::map<std::string, http_file *> objects;
	pthread_t *thread;

	http_file * lookup_url(std::string url);

public:
	web_server(std::string listen_interface, int listen_port);
	~web_server();

	void run();
};
