class http_file
{
public:
	http_file();
	~http_file();

	http_bundle * do_request(request_t request_type, http_bundle *request_details);
};
