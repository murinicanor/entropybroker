// SVN: $Id$
#define SCC_BUFFER_SIZE 4096

class scc
{
	int bytes_in, index;
	unsigned char buffer[SCC_BUFFER_SIZE];
	double threshold;

	char *user;

	double get_cur_scc();

public:
	scc();
	~scc();

	void set_user(char *puser);
	void set_threshold(double t);

	void add(unsigned char byte);
	bool is_ok();
	char *stats();
};
