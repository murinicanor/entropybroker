#include <gd.h>
#include <stdlib.h>
#include <string>

#include "error.h"
#include "graph.h"

graph::graph(std::string font_in) : font(font_in)
{
	ts = NULL;
	values = NULL;
	n_values = 0;
}

graph::~graph()
{
	free(ts);
	free(values);
}

void graph::calc_text_width(std::string font_descr, double font_height, std::string str, int *width, int *height)
{
	int brect[8];

	const char *err = gdImageStringFT(NULL, &brect[0], 0, (char *)font_descr.c_str(), font_height, 0., 0, 0, (char *)str.c_str());
	if (err)
		error_exit("Failed working with %s: %s", font_descr.c_str(), err);

	*width = brect[2] - brect[6];
	*height = brect[3] - brect[7];
}

void graph::draw_text(gdImagePtr im, std::string font_descr, double font_height, int color, std::string str, int x, int y)
{
	int brect[8];

	gdImageStringFT(im, &brect[0], color, (char *)font_descr.c_str(), font_height, 0., x, y, (char *)str.c_str());
}

void graph::do_draw(int width, int height, std::string title, char **result, int *result_len)
{
	int yAxisTop = (!title.empty()) ? 12 : 5;
	int yAxisBottom = height - 25;
	int yTicks = 10;
	int xTicks;
	int yAxisMaxStrLen = 5;
	int xAxisLeft;
	int xAxisRight = width - 5;
	int font_height = 10;

	gdImagePtr im = gdImageCreate(width, height);

	int black = gdImageColorAllocate(im, 0, 0, 0);
	int gray = gdImageColorAllocate(im, 127, 127, 127);
	int red = gdImageColorAllocate(im, 255, 0, 0);
	int white = gdImageColorAllocate(im, 255, 255, 255);

	// determine x-position of y-axis
        std::string dummyStr;
        for(int nr=0; nr<yAxisMaxStrLen; nr++)
                dummyStr += "8";
	int dummy;
	calc_text_width(font, font_height, dummyStr, &xAxisLeft, &dummy);

        // determine center of date string
	int dateWidth = -1;
	calc_text_width(font, 10.0, "8888/88/88", &dateWidth, &dummy);
        xTicks = (width - xAxisLeft) / dateWidth;

	double dataMin = 99999999999.9;
	double dataMax = -99999999999.9;
	double tMin = 99999999999.9;
	double tMax = -99999999999.9;

	for(int index=0; index<n_values; index++)
	{
		if (ts[index] < tMin) tMin = ts[index];
		if (values[index] < dataMin) dataMin = values[index];
		if (ts[index] > tMax) tMax = ts[index];
		if (values[index] > dataMax) dataMax = values[index];
	}

	double scaleX = (double)(xAxisRight - xAxisLeft) / (double)(tMax - tMin);
	double scaleY = (double)(yAxisBottom - yAxisTop) / (dataMax - dataMin);
	double scaleT = (double)(tMax - tMin) / (double)xTicks;

	if (!title.empty())
	{
		int textWidth = -1;
		calc_text_width(font, 10.0, title, &textWidth, &dummy);

		int plotX = (width / 2) - (textWidth / 2);

		draw_text(im, font, font_height, black, title, plotX, 9);
	}
}
