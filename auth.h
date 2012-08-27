int auth_eb_user(int fd, int to, users *user_map, std::string & password, long long unsigned int *challenge, bool is_proxy_auth);
int auth_eb(int fd, int to, users *user_map, std::string & password, long long unsigned int *challenge);
int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge);
int auth_client_server_user(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge);
bool get_auth_from_file(char *filename, std::string & username, std::string & password);
int auth_proxy(int fd_broker, int fd_client, int to, long long unsigned int *challenge);
