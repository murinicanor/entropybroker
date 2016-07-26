class stirrer_blowfish : public stirrer
{
private:
	encrypt_stream_blowfish enc;

public:
	stirrer_blowfish();
	~stirrer_blowfish();

	int get_ivec_size();
	int get_stir_size();
	void do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction);
};
