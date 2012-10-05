// SVN: $Revision$
class hasher
{
public:
	hasher();
	virtual ~hasher();

	virtual std::string get_name() = 0;

	static hasher *select_hasher(std::string type);

	virtual int get_hash_size() const = 0;
	virtual void do_hash(unsigned char *in, int in_size, unsigned char *dest) = 0;
};
