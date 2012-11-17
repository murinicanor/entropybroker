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
	std::map<std::string, user_t> *user_map;
	pthread_mutex_t lock;

	void load_usermap();

public:
	users(std::string filename);
	~users();

	void reload();

	bool find_user(std::string username, std::string & password, user_t **user);
};
