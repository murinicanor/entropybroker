// SVN: $Revision$
class ivec
{
private:
	int size;
	bit_count_estimator *bce;
	random_source_t rs;

	void init();

public:
	ivec(int size, bit_count_estimator *bce, random_source_t rs);
	ivec(FILE *fh, int size, bit_count_estimator *bce, random_source_t rs);
	~ivec();

	void dump(FILE *fh);

	void get(unsigned char *where_to);
	void seed(unsigned char *in, int n);

	bool needs_seeding() const;
};
