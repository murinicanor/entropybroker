// SVN: $Id$
class hasher
{
public:
	hasher();
	virtual ~hasher();

	virtual int get_hash_size() const = 0;
	virtual void do_hash(unsigned char *in, int in_size, unsigned char *dest) = 0;
};
