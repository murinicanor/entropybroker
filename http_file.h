class http_file
{
public:
	http_file();
	virtual ~http_file();

	virtual std::string get_url() = 0;

	virtual http_bundle * do_request(http_request_t request_type, http_bundle *request_details) = 0;
};
