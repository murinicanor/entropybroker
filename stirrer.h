// SVN: $Id$
class stirrer
{
public:
	stirrer();
	virtual ~stirrer();

	virtual int get_ivec_size() const = 0;
	virtual int get_stir_size() const = 0;
	virtual void do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction) = 0;
};
