class graph
{
protected:
	std::string font;

	void calc_text_width(std::string font_descr, double font_height, std::string str, int *width, int *height);
	void draw_text(gdImagePtr im, std::string font_descr, double font_height, int color, std::string str, int x, int y);
	std::string shorten(double value, bool round);

public:
	graph(std::string font_in);
	virtual ~graph();

	void do_draw(int width, int height, std::string title, long int *t, double *v, int n_values, char **result, size_t *result_len);
};
