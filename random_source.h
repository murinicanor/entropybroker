typedef enum { RS_OPENSSL, RS_DEV_URANDOM, RS_DEV_RANDOM } random_source_t;

void get_random(random_source_t rs, unsigned char *p, size_t n);
bool check_random_empty(random_source_t rs);
void seed_random(random_source_t rs, unsigned char *in, size_t n, double byte_count);
void dump_random_state(char *file);
void retrieve_random_state(char *file);
