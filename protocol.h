int reconnect_server_socket(char *host, int port, char *password, int *socket_fd, const char *type, char is_server);
int message_transmit_entropy_data(int socket_fd, unsigned char *bytes, int n_bytes);
