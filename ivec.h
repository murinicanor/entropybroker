class ivec
{
private:
	bit_count_estimator *bce;

	void init(void);

public:
	ivec(bit_count_estimator *bce);
	ivec(FILE *fh, bit_count_estimator *bce);
	~ivec();

	void dump(FILE *fh);

	void get(unsigned char *where_to);
	void seed(unsigned char *in, int n);

	bool needs_seeding();
};
