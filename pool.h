// SVN: $Id$
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
	stirrer *s;
	ivec *iv;

	pthread_mutex_t lck;
	pthread_cond_t cond;

public:
	pool(int new_pool_size_bytes, bit_count_estimator *bce, hasher *hclass, stirrer *sclass, random_source_t rs);
	pool(int pool_nr, FILE *fh, bit_count_estimator *bce, hasher *hclass, stirrer *sclass, random_source_t rs);
	~pool();
	void dump(FILE *fh);

	// this method returns a condition variable if this object
	// was already(!) locked and NULL if it is was not locked
	// and you're now the owner of the lock(!)
	pthread_cond_t * lock_object();
	pthread_cond_t * timed_lock_object(double max_time);
	void unlock_object();

	/* -1 if not full, 0 if full */
	int add_entropy_data(unsigned char *entropy_data, int n_bytes);
	/* returns number of bytes returned, set prng_ok to also return data when pool empty */
	int get_entropy_data(unsigned char *entropy_data, int n_bytes_requested, bool prng_ok);
	int get_get_size() const;
	int get_get_size_in_bits() const;
	int get_n_bits_in_pool() const;
	int get_pool_size() const;
	bool is_full() const;
	bool is_almost_full() const;
	int add_event(double ts, unsigned char *event_data, int n_event_data);
};
