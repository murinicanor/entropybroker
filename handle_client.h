// SVN: $Revision$
#define PIPE_CMD_HAVE_DATA 1
#define PIPE_CMD_NEED_DATA 2
#define PIPE_CMD_IS_FULL   3
#define PIPE_CMD_QUIT      4
extern const char *pipe_cmd_str[];

typedef struct
{
	int to_thread[2], to_main[2];
	pthread_t th;

	int socket_fd;
	std::string host, type;
	long long int id;
	bool is_server;
	int max_bits_per_interval;
	bool allow_prng;
	bool ignore_rngtest_fips140, ignore_rngtest_scc;
	double last_message, last_put_message;
	double connected_since;
	char *username, *password;

	fips140 *pfips140;
	scc *pscc;

	long long unsigned int ivec_counter;
	long long unsigned int challenge;
	encrypt_stream *stream_cipher;
	hasher *mac_hasher;

	pool_crypto *pc;

	int bits_sent, bits_recv;
	pthread_mutex_t stats_lck;

	// globals
	users *pu;
	config_t *config;
	pools *ppools;
	statistics *stats;
	fips140 *output_fips140;
	scc *output_scc;
} client_t;

typedef struct
{
	int fd_sender;
	unsigned char cmd;
} msg_pair_t;

client_t *find_client_by_id(std::vector<client_t *> *clients, long long int id_in);
void main_loop(std::vector<client_t *> *clients, pthread_mutex_t *clients_mutex, pools *ppools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc, pool_crypto *pc);
