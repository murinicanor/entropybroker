// SVN: $Revision$
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

	pthread_mutex_t lck;
	pthread_cond_t cond;

	unsigned char *alloc_ivec(pool_crypto *pc);
	void free_ivec(pool_crypto *pc, unsigned char *ivec);

public:
	pool(int new_pool_size_bytes, bit_count_estimator *bce, pool_crypto *pc);
	pool(int pool_nr, FILE *fh, bit_count_estimator *bce, pool_crypto *pc);
	~pool();
	void dump(FILE *fh);

	// this method returns a condition variable if this object
	// was already(!) locked and NULL if it is was not locked
	// and you're now the owner of the lock(!)
	pthread_cond_t * lock_object();
	pthread_cond_t * timed_lock_object(double max_time);
	void unlock_object();

	/* -1 if not full, 0 if full */
	int add_entropy_data(unsigned char *entropy_data, int n_bytes, pool_crypto *pc, int is_n_bits = -1);
	/* returns number of bytes returned, set prng_ok to also return data when pool empty */
	int get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, bool prng_ok, pool_crypto *pc);
	int get_get_size(pool_crypto *pc) const;
	int get_get_size_in_bits(pool_crypto *pc) const;
	int get_n_bits_in_pool() const;
	int get_pool_size() const;
	int get_pool_size_bytes() const;
	unsigned char *expose_contents(); // resets bit count to zero
	bool is_full() const;
	bool is_almost_full(pool_crypto *pc) const;
	int add_event(double ts, unsigned char *event_data, int n_event_data, pool_crypto *pc);
};
