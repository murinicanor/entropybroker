// SVN: $Revision$
#include <openssl/aes.h>

class encrypt_stream_aes : public encrypt_stream
{
private:
	unsigned char ivec[AES_BLOCK_SIZE];
	AES_KEY key_enc, key_dec;

public:
	encrypt_stream_aes();

	int get_ivec_size();
	void init(unsigned char *key, int key_len, unsigned char *ivec);

	std::string get_name();

        void encrypt(unsigned char *p, size_t len, unsigned char *p_out); 
        void decrypt(unsigned char *p, size_t len, unsigned char *p_out);
};
