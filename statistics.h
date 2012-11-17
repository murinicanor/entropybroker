// SVN: $Revision$

#define HISTORY_REMEMBER_N 128

class history_logins
{
public:
	std::string host, type, user;
	double time_logged_in, duration;
};

class statistics
{
private:
	char *file;
	fips140 *pfips140;
	scc *pscc;
	pools *ppools;

	pthread_mutex_t logins_lck;
	std::vector<history_logins> logins;

	pthread_mutex_t recv_lck;
	long long int total_recv, total_recv_sd, total_recv_in, total_recv_in_sd;
	int total_recv_requests;

	pthread_mutex_t sent_lck;
	long long int total_sent, total_sent_sd;
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

	pthread_mutex_t msg_cnt_lck;
	int msg_cnt;

	pthread_mutex_t time_lck;
	double last_message, last_put_message, last_get_message;
	double connected_since;

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
	void inc_msg_cnt();
	void track_sents(int cur_n_bits);
	void track_recvs(int n_bits_added, int n_bits_added_in);
	void emit_statistics_file(int n_clients);
	void emit_statistics_log(int n_clients, bool force_stats, int reset_counters_interval);
	void register_msg(bool is_put);
	void put_history_login(std::string host_in, std::string type_in, std::string user_in, double start_ts, double duration_in);

	int get_msg_cnt();
	int get_times_empty();
	int get_times_not_allowed();
	int get_times_full();
	int get_times_quota();
	void get_recvs(long long int *total_bits, int *n_reqs, long long int *total_bits_in);
	void get_sents(long long int *total_bits, int *n_sents);
	double get_last_msg_ts();
	double get_since_ts();
	double get_last_put_msg_ts();
	double get_last_get_msg_ts();
	double get_start_ts();
	std::vector<history_logins> get_login_history();
	void get_sent_avg_sd(double *avg, double *sd);
	void get_recv_avg_sd(double *avg, double *sd);
	void get_recv_in_avg_sd(double *avg, double *sd);
};
