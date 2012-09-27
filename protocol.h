// SVN: $Revision$
#define PROTOCOL_VERSION 6
#define TCP_SILENT_FAIL_TEST_INTERVAL 120
#define MAX_ERROR_SLEEP 12

#define MAX_IDLE_TIME 303

#define DEFAULT_BROKER_PORT 55225

#define DEFAULT_PROXY_LISTEN_PORT 12347

#define DEFAULT_COMM_TO 15

#define DATA_HASH_FUNC(x, y, z) SHA256(x, y, z)
#define DATA_HASH_LEN SHA256_DIGEST_LENGTH

int recv_length_data(int fd, char **data, int *len, double to);
int send_length_data(int fd, const char *data, int len, double to);
void make_msg(char *where_to, int code, int value);
void calc_ivec(const char *password, long long unsigned int rnd, long long unsigned int counter, unsigned char *dest);

class protocol
{
private:
	std::vector<std::string> *hosts;
	unsigned int host_index;
	std::string username, password;
	bool is_server;
	std::string type;
	double comm_time_out;
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
	protocol(std::vector<std::string> * hosts_in, std::string username, std::string password, bool is_server, std::string type, double comm_time_out);
	~protocol();

	int sleep_interruptable(double how_long);
	int message_transmit_entropy_data(unsigned char *bytes_in, int n_bytes);
	int request_bytes(char *where_to, int n_bits, bool fail_on_no_bits);
	void drop();
};
