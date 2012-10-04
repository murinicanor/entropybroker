// SVN: $Revision$
class encrypt_stream
{
private:
	unsigned char ivec[8];
	int ivec_offset;

public:
	encrypt_stream(unsigned char ivec[8]);
	virtual ~encrypt_stream() = 0;

	static encrypt_stream * select_cipher(std::string type, unsigned char *key, int key_len, unsigned char ivec[8]);

	virtual std::string get_name() = 0;

	virtual void encrypt(unsigned char *p_in, size_t len, unsigned char *p_out) = 0;
	virtual void decrypt(unsigned char *p_in, size_t len, unsigned char *p_out) = 0;
};
