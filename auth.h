// SVN: $Revision$
int auth_eb_user(int fd, int to, users *user_map, std::string & username, std::string & password, long long unsigned int *challenge, bool is_proxy_auth, bool *is_server_in, std::string & type, random_source_t rs, encrypt_stream *es, hasher *mac_hasher, std::string hash_hasher, int max_get_put_size);
int auth_eb(int fd, int to, users *user_map, std::string & username, std::string & password, long long unsigned int *challenge, bool *is_server_in, std::string & type, random_source_t rand_src, encrypt_stream *enc, hasher *mac, std::string handshake_hash, int max_get_put_size);
int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type, std::string & cd, std::string & mh, int *max_get_put_size_bytes);
int auth_client_server_user(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type, std::string & cd, std::string & mh, int *max_get_put_size_bytes);
bool get_auth_from_file(char *filename, std::string & username, std::string & password);
