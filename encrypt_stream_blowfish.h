// SVN: $Revision$
class encrypt_stream_blowfish
{
private:
	BF_KEY key;

public:
	encrypt_stream_blowfish(unsigned char *key, int key_len, unsigned char ivec[8]);

	std::string get_name();

        void encrypt(unsigned char *p, size_t len, unsigned char *p_out); 
        void decrypt(unsigned char *p, size_t len, unsigned char *p_out);
};
