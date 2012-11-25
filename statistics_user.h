// SVN: $Revision$

class statistics_user : public statistics
{
protected:
	double connected_since;

public:
	statistics_user();

	void register_msg(bool is_put);
};
