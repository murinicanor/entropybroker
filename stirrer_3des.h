// SVN: $Revision$
#define SET_KEY_ATTEMPTS 10

class stirrer_3des : public stirrer
{
private:
	void set_3des_key(DES_key_schedule *ks, unsigned char key_in[8]);

public:
	stirrer_3des(random_source_t rs);
	~stirrer_3des();

	int get_ivec_size() const;
	int get_stir_size() const;
	void do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction);
};
