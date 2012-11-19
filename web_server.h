void start_web_server(config_t *config, std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex, pools *ppools, statistics *ps, fips140 *pfips140, scc *pscc, data_logger *dl);

class web_server
{
private:
	int fd;
	std::map<std::string, http_file *> objects;

	void add_object(http_file *p);

public:
	web_server(config_t *config, std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex, pools *ppools, statistics *ps, fips140 *pfips140, scc *pscc, data_logger *dl);
	~web_server();

	http_file * lookup_url(std::string url);

	void run();
};
