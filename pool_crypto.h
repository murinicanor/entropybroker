class pool_crypto
{
private:
	stirrer *s;
	hasher *h;
	random_source *rs;

public:
	pool_crypto(stirrer_type st, hasher_type ht, random_source_t rst);
	~pool_crypto();

	stirrer * get_stirrer() { return s; }
	hasher * get_hasher() { return h; }
	random_source * get_random_source() { return rs; }
};
