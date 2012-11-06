void start_web_server(std::string listen_interface, int listen_port);

class web_server
{
private:
	int fd;
	std::map<std::string, http_file *> objects;
	pthread_t *thread;

	void add_object(http_file *p);

public:
	web_server(std::string listen_interface, int listen_port);
	~web_server();

	http_file * lookup_url(std::string url);

	void run();
};
