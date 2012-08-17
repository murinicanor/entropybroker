class hasher
{
public:
	hasher();
	~hasher();

	int get_hash_size() const;
	void do_hash(unsigned char *in, int in_size, unsigned char *dest);
};
