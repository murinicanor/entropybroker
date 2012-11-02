class web_server
{
private:
	int fd;

public:
	web_server(std::string listen_interface, int listen_port);
	~web_server();
};
