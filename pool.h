#define DEFAULT_POOL_SIZE_BITS	32768
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
	hasher *h;
	ivec *iv;

	int get_stir_size() const;
	void stir(unsigned char *ivec, unsigned char *what, int n, unsigned char *temp_buffer, bool direction);

public:
	pool(int new_pool_size_bytes, bit_count_estimator *bce, hasher *hclass);
	pool(int pool_nr, FILE *fh, bit_count_estimator *bce, hasher *hclass);
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
