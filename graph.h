class graph
{
protected:
	std::string font;
	long int *ts;
	int *values;
	int n_values;

	void calc_text_width(std::string font_descr, double font_height, std::string str, int *width, int *height);
	void draw_text(gdImagePtr im, std::string font_descr, double font_height, int color, std::string str, int x, int y);

public:
	graph(std::string font_in);
	virtual ~graph();

	virtual void retrieve_data() = 0;

	void do_draw(int width, int height, std::string title, char **result, int *result_len);
};
