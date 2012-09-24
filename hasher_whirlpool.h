// SVN: $Id$
class hasher_whirlpool : public hasher
{
public:
	hasher_whirlpool();
	~hasher_whirlpool();

	int get_hash_size() const;
	void do_hash(unsigned char *in, int in_size, unsigned char *dest);
};
