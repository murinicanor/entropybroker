class http_file_logfile : public http_file
{
private:
	std::vector<client_t *> *clients;
	pthread_mutex_t *clients_mutex;
	pools *ppools;
	statistics *ps;
	fips140 *pfips140;
	scc *pscc;

public:
	http_file_logfile(statistics *ps_in);
	~http_file_logfile();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
