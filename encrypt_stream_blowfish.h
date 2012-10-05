// SVN: $Revision$
#include <openssl/blowfish.h>

class encrypt_stream_blowfish : public encrypt_stream
{
private:
	BF_KEY key;

public:
	encrypt_stream_blowfish();

	void init(unsigned char *key, int key_len, unsigned char ivec[8]);

	std::string get_name();

        void encrypt(unsigned char *p, size_t len, unsigned char *p_out); 
        void decrypt(unsigned char *p, size_t len, unsigned char *p_out);
};
