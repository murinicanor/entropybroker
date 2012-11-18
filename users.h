// SVN: $Revision$

class user_t
{
public:
	std::string password;
	int max_get_bps;

	double last_get_message, allowance;
};

class users
{
private:
	std::string filename;
	int default_max_get_bps;
	std::map<std::string, user_t> *user_map;
	pthread_mutex_t lock;

	void load_usermap();
	user_t *find_user(std::string username);

public:
	users(std::string filename, int default_max_get_bps);
	~users();

	void reload();

	bool get_password(std::string username, std::string & password);
	int calc_max_allowance(std::string username, double now, int n_requested);
	void use_allowance(std::string username, int n);
	void cancel_allowance(std::string username);
};
