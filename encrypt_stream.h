// SVN: $Revision$
class encrypt_stream
{
public:
	encrypt_stream();
	virtual ~encrypt_stream();

	static encrypt_stream * select_cipher(std::string type);

	virtual int get_ivec_size() = 0;
	virtual int get_key_size() = 0;

	virtual bool init(unsigned char *key, int key_len, unsigned char *ivec, bool force=false) = 0;

	virtual std::string get_name() = 0;

	virtual void encrypt(unsigned char *p_in, int len, unsigned char *p_out) = 0;
	virtual void decrypt(unsigned char *p_in, int len, unsigned char *p_out) = 0;
};
