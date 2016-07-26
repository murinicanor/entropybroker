class http_file_users : public http_file
{
private:
	users *pusers;

public:
	http_file_users(users *pusers_in);
	~http_file_users();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
