// SVN: $Revision$
class hasher_md5 : public hasher
{
public:
	hasher_md5();
	~hasher_md5();

	std::string get_name();

	int get_hash_size() const;
	void do_hash(unsigned char *in, int in_size, unsigned char *dest);
};
