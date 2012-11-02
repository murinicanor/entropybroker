typedef enum { GET, POST } request_t;

class http_server
{
private:
	int fd;
	std::vector<std::string> request_headers;
	request_t request_type;
	unsigned char *request_data;
	int request_data_size;

public:
	http_server(int fd);
	~http_server();

	request_t get_request_type();

	http_bundle * get_request();

	void send_response(http_bundle *response);
	void terminate();
};
