class http_file_file : public http_file
{
private:
	std::string url, meta, file;

	void load_file(unsigned char **p, int *len);

public:
	http_file_file(std::string url_in, std::string meta_in, std::string file_in);
	virtual ~http_file_file();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, http_bundle *request_details);
};
