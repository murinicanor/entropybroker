#define POOL_SIZE	4096	// in bits

class pool
{
private:
	unsigned char entropy_pool[POOL_SIZE / 8];
	int bits_in_pool;

public:
	pool();
	~pool();
	/* -1 if not full, 0 if full */
	int add_entropy_data(unsigned char entropy_data[8]);
	int determine_number_of_bits_of_data(unsigned char *data, int n_bytes);
	/* -1 if not enough data available */
	int get_entropy_data(unsigned char entropy_data[8]);
	int get_n_bits_in_pool(void);
};
