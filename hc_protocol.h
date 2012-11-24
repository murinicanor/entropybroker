// SVN: $Revision$
int send_denied_empty(int fd, statistics *stats, config_t *config);
int send_denied_quota(int fd, statistics *stats, config_t *config);
int send_denied_full(int fd, statistics *stats, config_t *config, char *host);
int send_accepted_while_full(int fd, statistics *stats, config_t *config);
int send_got_data(int fd, pools *ppools, config_t *config);
int send_need_data(int fd, config_t *config);
int do_proxy_auth(client_t *client, users *user_map);
int do_client_get(client_t *client, bool *no_bits);
int do_client_put(client_t *client, bool *new_bits, bool *is_full);
int do_client_server_type(client_t *client);
int do_client_kernelpoolfilled_reply(client_t *client);
int do_client_kernelpoolfilled_request(client_t *client);
int do_client(client_t *p, bool *no_bits, bool *new_bits, bool *is_full);
int notify_server_full(int socket_fd, config_t *config);
int notify_client_data_available(int socket_fd, pools *ppools, config_t *config);
int notify_server_data_needed(int socket_fd, config_t *config);
