// SVN: $Revision$

class user_t
{
public:
	pthread_mutex_t lck;

	std::string username, password;
	int max_get_bps;

	statistics stats;
	statistics *stats_user() { return &stats; }

	double last_get_message, allowance;

	double last_logon;
};

class users
{
private:
	std::string filename;
	int default_max_get_bps;
	std::map<std::string, user_t> *user_map;
	pthread_rwlock_t rwlck;

	user_t dummy_user;

	void list_wlock();
	void list_wunlock();
	void list_rlock();
	void list_runlock();

	void load_usermap();
	user_t *find_user(std::string username);

public:
	users(std::string filename, int default_max_get_bps);
	~users();

	void reload();

	bool get_password(std::string username, std::string & password);
	int calc_max_allowance(std::string username, double now, int n_requested);
	bool use_allowance(std::string username, int n);
	bool cancel_allowance(std::string username);

	user_t *find_and_lock_user(std::string username);
	void unlock_user(user_t *u);

	std::vector<std::string> get_users();

	void set_last_login(std::string username, double when_ts);
	double get_last_login(std::string username);

	// user statistics
	void register_msg(std::string username, bool is_put);
	void inc_disconnects(std::string username);
	void inc_timeouts(std::string username);
	void inc_n_times_empty(std::string username);
	void inc_n_times_quota(std::string username);
	void inc_n_times_full(std::string username);
	void inc_bps_cur(std::string username);
	void inc_msg_cnt(std::string username);
	void inc_submit_while_full(std::string username);
	void inc_network_error(std::string username);
	void inc_protocol_error(std::string username);
	void inc_misc_errors(std::string username);
	void track_sents(std::string username, int cur_n_bits);
	void track_recvs(std::string username, int n_bits_added, int n_bits_added_in);

	int get_reset_bps_cur(std::string username);
	int get_msg_cnt(std::string username);
	int get_disconnects(std::string username);
	int get_times_empty(std::string username);
	int get_times_full(std::string username);
	int get_times_quota(std::string username);
	int get_submit_while_full(std::string username);
	int get_network_error(std::string username);
	int get_protocol_error(std::string username);
	int get_misc_errors(std::string username);
	void get_recvs(std::string username, long long int *total_bits, int *n_reqs, long long int *total_bits_in);
	void get_sents(std::string username, long long int *total_bits, int *n_sents);
	double get_last_msg_ts(std::string username);
	double get_last_put_msg_ts(std::string username);
	double get_last_get_msg_ts(std::string username);
	void get_sent_avg_sd(std::string username, double *avg, double *sd);
	void get_recv_avg_sd(std::string username, double *avg, double *sd);
	void get_recv_in_avg_sd(std::string username, double *avg, double *sd);
};
