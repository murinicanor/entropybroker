#define MEM_POOL_COUNTS VAR_DIR "/mem_pool_counts.dat"
#define MEM_POOL_BIT_COUNT_COUNTS VAR_DIR "/mem_pool_bit_count_counts.dat"
#define DSK_POOL_COUNTS VAR_DIR "/dsk_pool_counts.dat"
#define DSK_POOL_BIT_COUNT_COUNTS VAR_DIR "/dsk_pool_bit_count_counts.dat"
#define CONNECTION_COUNTS VAR_DIR "/connection_counts.dat"
#define RECV_BIT_COUNT VAR_DIR "/recv_bit_count.dat"
#define RECV_BIT_COUNT_IN VAR_DIR "/recv_bit_count_in.dat"
#define SENT_BIT_COUNT VAR_DIR "/sent_bit_count.dat"

#define MEASURE_INTERVAL 300
#define MEASURE_KEEP_N	((86400 / MEASURE_INTERVAL) * 7)

class data_logger
{
private:
	pthread_mutex_t mem_pool_lck;
	data_store_int *mem_pool_counts;

	pthread_mutex_t dsk_pool_lck;
	data_store_int *dsk_pool_counts;

	pthread_mutex_t connection_counts_lck;
	data_store_int *connection_counts;

	pthread_mutex_t mem_pool_bit_count_lck;
	data_store_int *mem_pool_bit_count_counts;

	pthread_mutex_t dsk_pool_bit_count_lck;
	data_store_int *dsk_pool_bit_count_counts;

	long long int prev_recv_n, prev_recv_in_n, prev_sent_n;

	pthread_mutex_t recv_bit_count_lck;
	data_store_int *recv_bit_count;

	pthread_mutex_t recv_bit_count_in_lck;
	data_store_int *recv_bit_count_in;

	pthread_mutex_t sent_bit_count_lck;
	data_store_int *sent_bit_count;

	pthread_t thread;

	pthread_mutex_t terminate_flag_lck;
	bool abort;

	///
	statistics *s;

	pools *ppools;

	std::vector<client_t *> *clients;
	pthread_mutex_t *clients_mutex;

	void dump_data();

public:
	data_logger(statistics *s_in, pools *ppools_in, std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in);
	~data_logger();

	void get_mem_pool_counts(long int **t, double **v, int *n);
	void get_dsk_pool_counts(long int **t, double **v, int *n);
	void get_connection_counts(long int **t, double **v, int *n);
	void get_pools_bitcounts(long int **t, double **v, int *n);
	void get_disk_pools_bitcounts(long int **t, double **v, int *n);
	void get_recv_bit_count(long int **t, double **v, int *n);
	void get_recv_bit_count_in(long int **t, double **v, int *n);
	void get_sent_bit_count(long int **t, double **v, int *n);

	void run();
};
