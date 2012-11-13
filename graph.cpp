#include <gd.h>
#include <stdlib.h>
#include <string>

#include "error.h"
#include "utils.h"
#include "graph.h"

graph::graph(std::string font_in) : font(font_in)
{
}

graph::~graph()
{
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

void graph::do_draw(int width, int height, std::string title, long int *ts, double *values, int n_values, char **result, size_t *result_len)
{
	int yAxisTop = (!title.empty()) ? 12 : 5;
	int yAxisBottom = height - 25;
	int yTicks = 10;
	int xTicks;
	unsigned int yAxisMaxStrLen = 4;
	bool doRound = false;
	int xAxisLeft;
	int xAxisRight = width - 5;
	int font_height = 10;

	gdImagePtr im = gdImageCreate(width, height);

	int black = gdImageColorAllocate(im, 0, 0, 0);
	int gray = gdImageColorAllocate(im, 127, 127, 127);
	int red = gdImageColorAllocate(im, 255, 0, 0);

        // determine center of date string
	int dateWidth = -1, dummy;
	calc_text_width(font, 10.0, "8888/88/88", &dateWidth, &dummy);

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

	// determine x-position of y-axis
        std::string dummyStr1 = format("%f", dataMax);
        std::string dummyStr2 = format("%f", dataMin);
	std::string use_width = dummyStr1;
	if (dummyStr2.size() > use_width.size())
		use_width = dummyStr2;
	size_t dot_index = use_width.find_first_of('.');
	if (dot_index == std::string::npos)
		dot_index = use_width.size();
	if (dot_index > yAxisMaxStrLen)
	{
		doRound = true;
		use_width = use_width.substr(0, dot_index);
	}
	else
	{
		use_width = use_width.substr(0, yAxisMaxStrLen);
	}
	calc_text_width(font, font_height, use_width, &xAxisLeft, &dummy);
	xAxisLeft++; // 1 pixel space between text and lines

        xTicks = (width - xAxisLeft) / dateWidth;

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

	gdImageLine(im, xAxisLeft, yAxisTop, xAxisLeft, yAxisBottom, black);
	gdImageLine(im, xAxisLeft, yAxisBottom, xAxisRight, yAxisBottom, black);

	// draw ticks horizonal
	for(int xti=0; xti<=xTicks; xti++)
	{
		int x = (double(xAxisRight - xAxisLeft) * double(xti)) / double(xTicks) + xAxisLeft;

		double value = tMin + scaleT * double(xti);

		time_t epoch = value * 1000;
		struct tm *tm = localtime(&epoch);

		char buffer[128];
		strftime(buffer, sizeof buffer, "%Y/%m/%d", tm);
		std::string strDate = std::string(buffer);
		strftime(buffer, sizeof buffer, "%H:%M:%S", tm);
		std::string strTime = std::string(buffer);

		if (xti > 0)
			gdImageLine(im, x, yAxisTop + 1, x, yAxisBottom, gray);

		int xPos = -1;
		if (xti == 0)
			xPos = mymax(0, x - dateWidth / 2);
		else if (xti == xTicks)
			xPos = width - (dateWidth * 3) / 4;
		else if (xti == xTicks - 1)
			xPos = x - (dateWidth * 5) / 8;
		else
			xPos = x - dateWidth / 2;

		draw_text(im, font, font_height, gray, strTime, xPos, yAxisBottom + 14);
		draw_text(im, font, font_height, gray, strDate, xPos, yAxisBottom + 24);

		gdImageLine(im, x, yAxisBottom, x, yAxisBottom + 2, black);
	}

	// draw ticks vertical
	for(int yti=0; yti<=yTicks; yti++)
	{
		int y = (double(yAxisBottom - yAxisTop) * double(yti)) / double(yTicks) + yAxisTop;
		gdImageLine(im, xAxisLeft - 2, y, xAxisLeft, y, black);

		double value = (((dataMax - dataMin) / double(yTicks)) * double(yTicks - yti) + dataMin);

		std::string str = format("%f", value);
		if (doRound)
		{
			size_t dot_offset = str.find_first_of('.');
			if (dot_offset != std::string::npos)
				str = str.substr(0, dot_offset);
		}
		else
		{
			str = str.substr(0, yAxisMaxStrLen);
		}

		gdImageLine(im, xAxisLeft + 1, y, xAxisRight, y, gray);

		draw_text(im, font, font_height, gray, str, 1, y == yAxisTop ? y + 6 : y + 3);
	}

	// draw data
	if (n_values > 1 && dataMax - dataMin > 0.001)
	{
		bool first = true;
		int yPrev = -1, xPrev = -1;
		for(int index=0; index<n_values; index++)
		{
			double t = ts[index];
			double value = values[index];
			int x = xAxisLeft + int(scaleX * double(t - tMin));
			int y = yAxisBottom - int(scaleY * double(value - dataMin));

			if (first)
			{
				xPrev = x;
				yPrev = y;
				first = false;
			}
			else
			{
				gdImageLine(im, xPrev, yPrev, x, y, red);
				xPrev = x;
				yPrev = y;
			}
		}
	}
	else
	{
		draw_text(im, font, font_height * 1.5, red, "No data or data too constant", xAxisLeft + 5, height / 2 + yAxisTop / 2);
	}

	// draw to memory
	FILE *fh = open_memstream(result, result_len);
	if (!fh)
		error_exit("graph: open_memstream failed");

	gdImagePng(im, fh);

	fclose(fh);

	gdImageDestroy(im);
}
