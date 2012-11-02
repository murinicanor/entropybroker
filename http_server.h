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
	std::vector<std::string> get_request_headers();
	int get_request_data_size();
	unsigned char *get_request_data();

	void send_response(std::vector<std::string> response_headers, unsigned char *response_data, int response_data_size);
	void terminate();
};
