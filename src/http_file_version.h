class http_file_version : public http_file
{
public:
	http_file_version();
	~http_file_version();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
