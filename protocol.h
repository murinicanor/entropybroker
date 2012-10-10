// SVN: $Revision$
#define PROTOCOL_VERSION 7
#define TCP_SILENT_FAIL_TEST_INTERVAL 120
#define MAX_ERROR_SLEEP 12

#define MAX_IDLE_TIME 303

#define DEFAULT_BROKER_PORT 55225

#define DEFAULT_PROXY_LISTEN_PORT 12347

#define DEFAULT_COMM_TO 15

int recv_length_data(int fd, char **data, unsigned int *len, double to);
int send_length_data(int fd, const char *data, unsigned int len, double to);
void make_msg(unsigned char *where_to, unsigned int code, unsigned int value);
void calc_ivec(const char *password, long long unsigned int rnd, long long unsigned int counter, size_t ivec_size, unsigned char *dest);

typedef enum { RSS_STILL_CONNECTED = 1, RSS_NEW_CONNECTION, RSS_FAIL } reconnect_status_t;

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
	int pingnr;
	int socket_fd;
	int sleep_9003;
	long long unsigned ivec_counter, challenge;
	//
	unsigned int max_get_put_size;

	encrypt_stream *stream_cipher;
	hasher *mac_hasher;

	void do_encrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
	void do_decrypt(unsigned char *buffer_in, unsigned char *buffer_out, int n_bytes);
	reconnect_status_t reconnect_server_socket();
	void error_sleep(int count);

public:
	protocol(std::vector<std::string> * hosts_in, std::string username, std::string password, bool is_server, std::string type, double comm_time_out);
	~protocol();

	unsigned int get_max_get_put_size() { return max_get_put_size; }
	int sleep_interruptable(double how_long);
	int message_transmit_entropy_data(unsigned char *bytes_in, unsigned int n_bytes);
	int request_bytes(unsigned char *where_to, unsigned int n_bits, bool fail_on_no_bits);
	void drop();
};
