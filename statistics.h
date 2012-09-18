class statistics
{
private:
	char *file;

	int bps, bps_cur;

	long long int total_recv, total_sent;
	int total_recv_requests, total_sent_requests;
	int n_times_empty, n_times_not_allowed, n_times_full, n_times_quota;

	int disconnects, timeouts;

	pthread_mutex_t lck;

public:
	statistics();
	~statistics();

	void inc_disconnects();
	void inc_timeouts();
};
