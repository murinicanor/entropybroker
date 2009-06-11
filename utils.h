#define min(x, y)       ((x)<(y)?(x):(y))
#define max(x, y)       ((x)>(y)?(x):(y))

int READ(int fd, char *whereto, size_t len);
int WRITE(int fd, char *whereto, size_t len);
int start_listen(char *adapter, int portnr);
int connect_to(char *host, int portnr);
int myrand(int max);
double get_ts(void);
