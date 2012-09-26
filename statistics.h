// SVN: $Revision$
class statistics
{
private:
	char *file;
	fips140 *pfips140;
	scc *pscc;
	pools *ppools;

	pthread_mutex_t recv_lck;
	long long int total_recv;
	int total_recv_requests;

	pthread_mutex_t sent_lck;
	long long int total_sent;
	int total_sent_requests;
	int bps_cur;

	pthread_mutex_t times_empty_lck;
	int n_times_empty;

	pthread_mutex_t times_not_allowed_lck;
	int n_times_not_allowed;

	pthread_mutex_t times_full_lck;
	int n_times_full;

	pthread_mutex_t times_quota_lck;
	int n_times_quota;

	pthread_mutex_t disconnects_lck;
	int disconnects;

	pthread_mutex_t timeouts_lck;
	int timeouts;

	double start_ts;

	void lock_all();
	void unlock_all();

public:
	statistics(char *file_in, fips140 *fips140_in, scc *scc_in, pools *pp_in);
	~statistics();

	void inc_disconnects();
	void inc_timeouts();
	void inc_n_times_empty();
	void inc_n_times_quota();
	void inc_n_times_full();
	void inc_bps_cur();
	void track_sents(int cur_n_bits);
	void track_recvs(int n_bits_added);
	void emit_statistics_file(int n_clients);
	void emit_statistics_log(int n_clients, bool force_stats, int reset_counters_interval);
};
