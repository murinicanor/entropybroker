#define DEFAULT_POOL_SIZE_BITS	16384
#define MAX_EVENT_BITS	11

typedef struct
{
        double last_time;
        double last_delta, last_delta2;
} event_state_t;

class pool
{
private:
	unsigned char *entropy_pool;
	int pool_size_bytes;
	int bits_in_pool;
	event_state_t state;
	bit_count_estimator *bce;
	ivec *iv;

public:
	pool(bit_count_estimator *bce);
	pool(int pool_nr, FILE *fh, bit_count_estimator *bce);
	~pool();
	void dump(FILE *fh);

	/* -1 if not full, 0 if full */
	int add_entropy_data(unsigned char *entropy_data, int n_bytes);
	/* returns number of bytes returned, set prng_ok to also return data when pool empty */
	int get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, bool prng_ok);
	int get_get_size(void);
	int get_get_size_in_bits(void);
	int get_n_bits_in_pool(void);
	int get_pool_size(void);
	bool is_full(void);
	bool is_almost_full(void);
	int add_event(double ts, unsigned char *event_data, int n_event_data);
};
