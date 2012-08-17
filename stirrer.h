class stirrer
{
public:
	stirrer();
	~stirrer();

	int get_stir_size() const;
	void do_stir(unsigned char *ivec, unsigned char *what, int n, unsigned char *temp_buffer, bool direction);
};
