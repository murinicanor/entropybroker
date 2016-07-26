enum bit_count_estimator_type_t { BCE_SHANNON, BCE_COMPRESSION };

class bit_count_estimator
{
private:
	const bit_count_estimator_type_t type;

	int determine_number_of_bits_of_data_shannon(const unsigned char *const data, const unsigned int n_bytes);
	int determine_number_of_bits_of_data_compression(const unsigned char *const data, const unsigned int n_bytes);

public:
	bit_count_estimator(const bit_count_estimator_type_t type_in);

	int get_bit_count(const unsigned char *const data, const unsigned int n_bytes);
};
