// SVN: $Revision$
#include <openssl/camellia.h>

#define CAMELLIA_MAX_KEY_SIZE (256 / 8)

class encrypt_stream_camellia : public encrypt_stream
{
private:
	int ivec_offset;
	unsigned char ivec[CAMELLIA_BLOCK_SIZE];
	CAMELLIA_KEY key;

public:
	encrypt_stream_camellia();

	int get_ivec_size();
	int get_key_size();

	bool init(unsigned char *key, int key_len, unsigned char *ivec, bool force=false);

	std::string get_name();

        void encrypt(unsigned char *p, size_t len, unsigned char *p_out); 
        void decrypt(unsigned char *p, size_t len, unsigned char *p_out);
};
