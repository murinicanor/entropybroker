class http_file_version : public http_file
{
public:
	http_file_version();
	~http_file_version();

	std::string get_url();

	http_bundle * do_request(request_t request_type, http_bundle *request_details);
};
