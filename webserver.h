class webserver
{
private:
	int fd;

public:
	webserver(std::string listen_interface, int listen_port);
	~webserver();
};
