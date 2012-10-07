// SVN: $Revision$
int auth_eb_user(int fd, int to, users *user_map, std::string & username, std::string & password, long long unsigned int *challenge, bool is_proxy_auth, bool *is_server_in, std::string & type, random_source_t rs, encrypt_stream *es, hasher *mac_hasher, std::string hash_hasher);
int auth_eb(int fd, int to, users *user_map, std::string & username, std::string & password, long long unsigned int *challenge, bool *is_server_in, std::string & type, random_source_t rand_src, encrypt_stream *enc, hasher *mac, std::string handshake_hash);
int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type, std::string & cd, std::string & mh);
int auth_client_server_user(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type, std::string & cd, std::string & mh);
bool get_auth_from_file(char *filename, std::string & username, std::string & password);
