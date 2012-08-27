#define PROTOCOL_VERSION 4
#define TCP_SILENT_FAIL_TEST_INTERVAL 120
#define MAX_ERROR_SLEEP 12

#define DEFAULT_BROKER_PORT 55225

#define DEFAULT_PROXY_LISTEN_PORT 12347

#define DEFAULT_COMM_TO 15

#define DATA_HASH_FUNC(x, y, z) SHA256(x, y, z)
#define DATA_HASH_LEN SHA256_DIGEST_LENGTH

void make_msg(char *where_to, int code, int value);
void calc_ivec(char *password, long long unsigned int rnd, long long unsigned int counter, unsigned char *dest);

class protocol
{
private:
	char *host;
	int port;
	std::string username, password;
	bool is_server;
	std::string type;
	//
	int socket_fd;
	int sleep_9003;
	unsigned char ivec[8];
	long long unsigned ivec_counter, challenge;
	int ivec_offset;
	BF_KEY key;

	void do_encrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
	void do_decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
	void init_ivec(std::string password, long long unsigned int rnd, long long unsigned int counter);
	int reconnect_server_socket();
	void set_password(std::string password);
	void error_sleep(int count);

public:
	protocol(const char *host, int port, std::string username, std::string password, bool is_server, std::string type);
	~protocol();

	int sleep_interruptable(int how_long);
	int message_transmit_entropy_data(unsigned char *bytes_in, int n_bytes);
	int request_bytes(char *where_to, int n_bits, bool fail_on_no_bits);
	void drop();
	bool proxy_auth_user(std::string username, std::string password);
};
