int auth_eb(int fd, int to, std::map<std::string, std::string> *users);
char * get_password_from_file(char *filename);
int auth_client_server(int fd, int to, std::string & username, std::string & password);
