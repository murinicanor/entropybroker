#define PROTOCOL_VERSION 4
#define TCP_SILENT_FAIL_TEST_INTERVAL 120
#define MAX_ERROR_SLEEP 12

#define DATA_HASH_FUNC(x, y, z) SHA256(x, y, z)
#define DATA_HASH_LEN SHA256_DIGEST_LENGTH

void make_msg(char *where_to, int code, int value);
int reconnect_server_socket(char *host, int port, std::string username, std::string password, int *socket_fd, const char *type, char is_server);
void set_password(std::string password);
void calc_ivec(char *password, long long unsigned int rnd, long long unsigned int counter, unsigned char *dest);
int sleep_interruptable(int socket_fd, int how_long);
int message_transmit_entropy_data(char *host, int port, int *socket_fd, std::string username, std::string password, const char *server_type, unsigned char *bytes_in, int n_bytes);
void decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
int request_bytes(int *socket_fd, char *host, int port, std::string username, std::string password, const char *client_type, char *where_to, int n_bits, bool fail_on_no_bits);
void insert_hash(unsigned char **in, int in_len, int *out_len);
