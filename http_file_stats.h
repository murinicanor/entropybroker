class http_file_stats : public http_file
{
private:
	std::vector<client_t *> *clients;
	pthread_mutex_t *clients_mutex;

public:
	http_file_stats(std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex);
	~http_file_stats();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
