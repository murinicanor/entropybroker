#define SET_KEY_ATTEMPTS 10

class stirrer_3des : public stirrer
{
private:
	encrypt_stream_3des enc;

public:
	stirrer_3des();
	~stirrer_3des();

	int get_ivec_size();
	int get_stir_size();
	void do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction);
};
