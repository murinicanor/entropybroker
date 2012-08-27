class users
{
private:
	std::string file;
	std::map<std::string, std::string> *user_map;

	void load_usermap();

public:
	users(std::string file);
	~users();

	bool find_user(std::string username, std::string & password);
};
