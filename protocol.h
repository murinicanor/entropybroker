#define PROTOCOL_VERSION 2
#define TCP_SILENT_FAIL_TEST_INTERVAL 120

int reconnect_server_socket(char *host, int port, char *password, int *socket_fd, const char *type, char is_server);
void set_password(char *password);
int message_transmit_entropy_data(int socket_fd, unsigned char *bytes, int n_bytes);
void decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
