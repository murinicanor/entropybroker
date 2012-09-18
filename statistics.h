class statistics
{
private:
	char *file;
	fips140 *pfips140;
	scc *pscc;
	pools *ppools;

	int bps, bps_cur;

	long long int total_recv, total_sent;
	int total_recv_requests, total_sent_requests;
	int n_times_empty, n_times_not_allowed, n_times_full, n_times_quota;

	int disconnects, timeouts;

	pthread_mutex_t lck;

	double start_ts;

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
	void emit_statistics_log(std::vector<client_t *> *clients, bool force_stats, int reset_counters_interval);
};
