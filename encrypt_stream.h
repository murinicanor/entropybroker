// SVN: $Revision$
class encrypt_stream
{
protected:
	unsigned char ivec[8];
	int ivec_offset;

public:
	encrypt_stream();
	virtual ~encrypt_stream();

	static encrypt_stream * select_cipher(std::string type);
	virtual void init(unsigned char *key, int key_len, unsigned char ivec[8]);

	virtual std::string get_name() = 0;

	virtual void encrypt(unsigned char *p_in, size_t len, unsigned char *p_out) = 0;
	virtual void decrypt(unsigned char *p_in, size_t len, unsigned char *p_out) = 0;
};
