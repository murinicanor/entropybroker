// SVN: $Revision$
#include <openssl/camellia.h>

class encrypt_stream_camellia : public encrypt_stream
{
private:
	int ivec_offset;
	unsigned char ivec[8];
	CAMELLIA_KEY key;

public:
	encrypt_stream_camellia();

	int get_ivec_size();
	int get_key_size();

	bool init(unsigned char *key, int key_len, unsigned char *ivec);

	std::string get_name();

        void encrypt(unsigned char *p, size_t len, unsigned char *p_out); 
        void decrypt(unsigned char *p, size_t len, unsigned char *p_out);
};
