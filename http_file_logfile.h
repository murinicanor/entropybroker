class http_file_logfile : public http_file
{
private:
	statistics_global *ps;

public:
	http_file_logfile(statistics_global *ps_in);
	~http_file_logfile();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
