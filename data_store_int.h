class data_store_int
{
private:
	long long int *values;
	int *counts;
	bool *valid;
	int n_samples, interval;
	int cur_t;

	int init_data(int t);

public:
	data_store_int(int n_samples, int interval);
	data_store_int(std::string file);
	~data_store_int();

	void dump(std::string file);

	void add_avg(int t, int value);
	void add_sum(int t, int value);
	bool get(int index, double *value);

	void get_data(long int **t, double **v, int *n);

	int get_cur_t() { return cur_t; }
	int get_n_samples() { return n_samples; }
	int get_interval() { return interval; }
};
