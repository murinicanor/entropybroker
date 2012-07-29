class scc
{
	int bytes_in, index;
	unsigned char buffer[POOL_SIZE/8];
	double threshold;

	char *user;

	double get_cur_scc(void);

public:
	scc();
	~scc();

	void set_user(char *puser);
	void set_threshold(double t);

	void add(unsigned char byte);
	bool is_ok(void);
	char *stats(void);
};
