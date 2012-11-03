#define HTTP_SERVER_READ_SIZE 4096

class http_server
{
private:
	int fd;
	std::vector<std::string> request_headers;
	http_request_t request_type;
	unsigned char *request_data;
	int request_data_size;

public:
	http_server(int fd);
	~http_server();

	http_request_t get_request_type();
	http_bundle * get_request();

	void send_response(int status_code, http_bundle *response);
};
