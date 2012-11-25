// SVN: $Revision$

#define HISTORY_REMEMBER_N 128

typedef enum { HL_LOGIN_OK, HL_LOGOUT_OK, HL_LOGIN_USER_FAIL, HL_LOGIN_PW_FAIL, HL_LOGIN_OTHER } hl_type_t;

extern double start_ts;
double get_start_ts();

class history_logins
{
public:
	hl_type_t hl;
	std::string host, type, user;
	double time_logged_in, duration, event_ts;
	std::string details;
};

class statistics_global : public statistics
{
protected:
	pthread_mutex_t logins_lck;
	std::vector<history_logins> logins;

public:
	void put_history_log(hl_type_t, std::string host_in, std::string type_in, std::string user_in, double start_ts, double duration_in, std::string details);
	std::vector<history_logins> get_login_history();
};
