class http_file_users : public http_file
{
private:
	std::vector<client_t *> *clients;
	pthread_mutex_t *clients_mutex;
	users *pusers;

public:
	http_file_users(std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in, users *pusers_in);
	~http_file_users();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
