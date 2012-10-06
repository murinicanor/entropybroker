// SVN: $Revision$
class stirrer_aes : public stirrer
{
private:
	encrypt_stream_aes enc;

public:
	stirrer_aes();
	~stirrer_aes();

	int get_ivec_size();
	int get_stir_size();
	void do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction);
};
