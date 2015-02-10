#define mymin(x, y)       ((x)<(y)?(x):(y))
#define mymax(x, y)       ((x)>(y)?(x):(y))

extern pthread_mutexattr_t global_mutex_attr;

double get_ts(void);
long double get_ts_ns(void);
int READ(int fd, char *whereto, size_t len, bool *do_exit = NULL);
int READ(int fd, unsigned char *whereto, size_t len, bool *do_exit = NULL);
int READ_TO(int fd, char *whereto, size_t len, double to, bool *do_exit = NULL);
int READ_TO(int fd, unsigned char *whereto, size_t len, double to, bool *do_exit = NULL);
int WRITE(int fd, const char *whereto, size_t len, bool *do_exit = NULL);
int WRITE(int fd, const unsigned char *whereto, size_t len, bool *do_exit = NULL);
int WRITE_TO(int fd, const char *whereto, size_t len, double to, bool *do_exit = NULL);
int WRITE_TO(int fd, const unsigned char *whereto, size_t len, double to, bool *do_exit = NULL);
int start_listen(const char *adapter, int portnr, int listen_queue_size);
int connect_to(const char *host, int portnr);
void disable_nagle(int fd);
void enable_tcp_keepalive(int fd);
double mydrand();
int myrand();
int myrand(int max);
void write_pid(const char *file);
void start_process(const char *shell, const char *cmd, int *fd, pid_t *pid);
void no_core();
void lock_mem(void *p, int size);
void unlock_mem(void *p, int size);
void hexdump(unsigned char *in, int n);
void split_resource_location(std::string in, std::string & host, int & port);
void set_fd_nonblocking(int fd);
std::string get_endpoint_name(int fd);
void my_mutex_lock(pthread_mutex_t *mutex);
void my_mutex_unlock(pthread_mutex_t *mutex);
void set_thread_name(std::string name);
std::string get_thread_name(pthread_t *thread);
std::string get_current_thread_name();
void my_yield();
void pthread_check(int rc, const char *name);
void pthread_check(int rc, const char *name, int ok[]);
bool file_exist(const char *file);
void split_string(const char *in, const char *split, char ***out, int *n_out);
std::vector<std::string> split_string(std::string in, std::string split);
unsigned int uchar_to_uint(unsigned char *in);
bool recv_uint(int fd, unsigned int *value, double to);
void uint_to_uchar(unsigned int value, unsigned char *out);
bool send_uint(int fd, unsigned int value, double to);
void *malloc_locked(size_t n);
void free_locked(void *p, size_t n);
std::string format(const char *fmt, ...);
int get_local_port(int fd);
std::string time_to_str(time_t t);
bool get_bool(FILE *fh, bool *value);
bool get_int(FILE *fh, int *value);
bool get_long_long_int(FILE *fh, long long int *value);
void put_bool(FILE *fh, bool value);
void put_int(FILE *fh, int value);
void put_long_long_int(FILE *fh, long long int value);

void my_Assert(bool flag, int line, const char *file);
#define my_assert(x) my_Assert(x, __LINE__,  __FILE__)
void my_Assert2(bool flag, int line, const char *file, int debug_value);
#define my_assert2(x, y) my_Assert2(x, __LINE__,  __FILE__, y)

pid_t gettid();
