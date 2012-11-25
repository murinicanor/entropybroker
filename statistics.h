// SVN: $Revision$

class statistics
{
protected:
	pthread_mutex_t recv_lck;
	long long int total_recv, total_recv_sd, total_recv_in, total_recv_in_sd;
	int total_recv_requests;

	pthread_mutex_t sent_lck;
	long long int total_sent, total_sent_sd;
	int total_sent_requests;
	int bps_cur;

	pthread_mutex_t times_empty_lck;
	int n_times_empty;

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

	pthread_mutex_t submit_while_full_lck;
	int submit_while_full;

	pthread_mutex_t network_error_lck;
	int network_error;

	pthread_mutex_t protocol_error_lck;
	int protocol_error;

	pthread_mutex_t misc_errors_lck;
	int misc_errors;

	pthread_mutex_t time_lck;
	double last_message, last_put_message, last_get_message;

public:
	statistics();
	virtual ~statistics();

	void inc_disconnects();
	void inc_timeouts();
	void inc_n_times_empty();
	void inc_n_times_quota();
	void inc_n_times_full();
	void inc_bps_cur();
	void inc_msg_cnt();
	void inc_submit_while_full();
	void inc_network_error();
	void inc_protocol_error();
	void inc_misc_errors();
	void track_sents(int cur_n_bits);
	void track_recvs(int n_bits_added, int n_bits_added_in);
	void register_msg(bool is_put);

	int get_reset_bps_cur();
	int get_msg_cnt();
	int get_disconnects();
	int get_times_empty();
	int get_times_full();
	int get_times_quota();
	int get_submit_while_full();
	int get_network_error();
	int get_protocol_error();
	int get_misc_errors();
	void get_recvs(long long int *total_bits, int *n_reqs, long long int *total_bits_in);
	void get_sents(long long int *total_bits, int *n_sents);
	double get_last_msg_ts();
	double get_last_put_msg_ts();
	double get_last_get_msg_ts();
	void get_sent_avg_sd(double *avg, double *sd);
	void get_recv_avg_sd(double *avg, double *sd);
	void get_recv_in_avg_sd(double *avg, double *sd);
};
