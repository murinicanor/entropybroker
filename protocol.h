#define PROTOCOL_VERSION 3
#define TCP_SILENT_FAIL_TEST_INTERVAL 120

void make_msg(char *where_to, int code, int value);
int reconnect_server_socket(char *host, int port, char *password, int *socket_fd, const char *type, char is_server);
void set_password(char *password);
int sleep_interruptable(int socket_fd, int how_long);
int message_transmit_entropy_data(char *host, int port, int *socket_fd, char *password, const char *server_type, unsigned char *bytes_in, int n_bytes);
void decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
int request_bytes(int *socket_fd, char *host, int port, char *password, const char *client_type, char *where_to, int n_bits, bool fail_on_no_bits);
