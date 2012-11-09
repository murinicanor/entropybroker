class http_bundle
{
	std::vector<std::string> headers;
	unsigned char *data;
	int data_len;

public:
	http_bundle(std::vector<std::string> headers, unsigned char *data, int data_len);
	http_bundle(std::vector<std::string> headers, const char *data);
	http_bundle(std::vector<std::string> headers, std::string data);
	~http_bundle();

	std::vector<std::string> get_headers();
	int get_data_len();
	unsigned char *get_data();
};
