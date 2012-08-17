class stirrer_blowfish
{
public:
	stirrer_blowfish();
	~stirrer_blowfish();

	int get_stir_size() const;
	void do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction);
};
