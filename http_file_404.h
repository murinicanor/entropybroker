class http_file_404 : public http_file
{
public:
	http_file_404();
	~http_file_404();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, http_bundle *request_details);
};
