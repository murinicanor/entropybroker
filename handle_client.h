#define PIPE_CMD_HAVE_DATA 1
#define PIPE_CMD_NEED_DATA 2
#define PIPE_CMD_IS_FULL   3
const char *pipe_cmd_str[] = { NULL, "have data (1)", "need data (2)", "is full (3)" };

typedef struct
{
	int to_thread[2], to_main[2];
	pthread_t th;

	int socket_fd;
	char host[128], type[128];
	bool is_server, type_set;
	int max_bits_per_interval;
	bool allow_prng;
	bool ignore_rngtest_fips140, ignore_rngtest_scc;
	double last_message, last_put_message;
	double connected_since;
	char *password;

	fips140 *pfips140;
	scc *pscc;

	unsigned char ivec[8]; // used for data encryption
	int ivec_offset;
	long long unsigned int challenge;
	long long unsigned int ivec_counter; // required for CFB
	BF_KEY key;

	int bits_sent, bits_recv;
	pthread_mutex_t stats_lck;

	int ping_nr;

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

void main_loop(pools *ppools, config_t *config, fips140 *eb_output_fips140, scc *eb_output_scc);
