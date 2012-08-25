int auth_eb_user(int fd, int to, std::map<std::string, std::string> *users, std::string & password, long long unsigned int *challenge, bool is_proxy_auth);
int auth_eb(int fd, int to, std::map<std::string, std::string> *users, std::string & password, long long unsigned int *challenge);
int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge);
bool get_auth_from_file(char *filename, std::string & username, std::string & password);
std::map<std::string, std::string> * load_usermap(std::string filename);
