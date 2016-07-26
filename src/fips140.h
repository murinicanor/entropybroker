class fips140
{
	/* ringbuffer of 20000 bits */
	unsigned char fips140_rval[20000/8];
	/* point to current, ehr, thing */
	int fips140_p;
	/* number of bits in ringbuffer */
	int fips140_nbits;
	/* number of new bits after a long-test */
	int fips140_nnewbits;

	/* number of bits set to 1 (monobit test) */
	int fips140_n1;

	/* for poker test */
	int fips140_pokerbuf[16];

	/* where to store statistics */
	struct
	{
		int monobit;
		int poker;
		int longrun;
		int runs;
	} stats_t;

	int fips_version;
	char *user;

	static unsigned char fips140_bit1cnt[256];

	bool fips140_shorttest();
	bool fips140_longtest();

public:
	fips140();
	~fips140();

	static void init();

	void set_fips_version(int version);
	void set_user(const char *puser);

	void add(unsigned char newval);
	bool is_ok();
	char *stats();
};
