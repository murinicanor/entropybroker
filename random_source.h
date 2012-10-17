// SVN: $Revision$
#include <cryptopp/osrng.h>

typedef enum { RS_CRYPTOPP, RS_DEV_URANDOM, RS_DEV_RANDOM } random_source_t;

class random_source
{
private:
	random_source_t rs;
	CryptoPP::AutoSeededRandomPool rng;
	std::string state_file;

	void dump_state(std::string file);
	void retrieve_state(std::string file);

public:
	random_source(random_source_t rst);
	random_source(random_source_t rst, std::string dump_file_in);
	~random_source();

	void get(unsigned char *p, size_t n);
	bool check_empty();
	void seed(unsigned char *in, size_t n, double byte_count);
};
