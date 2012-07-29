class fips140
{
	/* array with numberofbitssetto1 */
	char fips140_bit1cnt[256];

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

	bool fips140_shorttest(void);
	bool fips140_longtest(void);

public:
	fips140();
	~fips140();

	void set_fips_version(int version);
	void set_user(char *puser);

	void add(unsigned char newval);
	bool is_ok(void);
	char *stats(void);
};
