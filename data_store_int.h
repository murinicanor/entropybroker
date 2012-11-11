class data_store_int
{
private:
	long long int *values;
	int *counts;
	int n_samples, interval;
	int prev_index;

	int get_int(FILE *fh);
	long long int get_long_long_int(FILE *fh);
	void put_int(FILE *fh, int value);
	void put_long_long_int(FILE *fh, long long int value);

public:
	data_store_int(int n_samples, int interval);
	data_store_int(std::string file);
	~data_store_int();

	void dump(std::string file);

	void add_avg(int t, int value);
	void add_sum(int t, int value);
	bool get(int index, double *value);

	int get_n_samples() { return n_samples; }
	int get_interval() { return interval; }
};
