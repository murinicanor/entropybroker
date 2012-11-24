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

	std::map<std::string, user_t> get_usermap();
};
