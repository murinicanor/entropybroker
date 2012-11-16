class http_file_graph_data_logger : public http_file
{
private:
	data_logger *dl;
	graph *g;

public:
	http_file_graph_data_logger(data_logger *dl_in, std::string font);
	~http_file_graph_data_logger();

	std::string get_url();

	std::string get_meta_type();

	http_bundle * do_request(http_request_t request_type, std::string request_url, http_bundle *request_details);
};
