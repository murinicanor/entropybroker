#define HTTP_SERVER_READ_SIZE 4096

class http_server
{
private:
	int fd;
	std::vector<std::string> request_headers;
	http_request_t request_type;
	unsigned char *request_data;
	std::string request_url;
	int request_data_size;

	bool send(unsigned char *p, int len);
	bool send(const char *what);

public:
	http_server(int fd);
	~http_server();

	http_request_t get_request_type();
	http_bundle * get_request();
	std::string get_request_url();

	void send_response(int status_code, std::vector<std::string> *headers, http_bundle *response);
};
