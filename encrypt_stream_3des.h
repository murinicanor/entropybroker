// SVN: $Revision$
#include <openssl/des.h>

class encrypt_stream_3des : public encrypt_stream
{
private:
	int ivec_offset;
	DES_cblock iv;
        DES_key_schedule ks1, ks2, ks3;

public:
	encrypt_stream_3des();

	int get_ivec_size();
	int get_key_size();

	bool init(unsigned char *key, int key_len, unsigned char *ivec, bool force=false);

	std::string get_name();

        void encrypt(unsigned char *p, size_t len, unsigned char *p_out); 
        void decrypt(unsigned char *p, size_t len, unsigned char *p_out);
};
