class http_file
{
public:
	http_file();
	virtual ~http_file();

	virtual http_bundle * do_request(request_t request_type, http_bundle *request_details) = 0;
};
