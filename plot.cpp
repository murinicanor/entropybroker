// SVN: $Id$
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
//extern "C" {
#include <png.h>
//}

#define minval(x, y) ((x) < (y) ? (x) : (y))
#define maxval(x, y) ((x) > (y) ? (x) : (y))

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		fprintf(stderr, "Usage: %s file_in.dat result.png\n", argv[0]);

		return 1;
	}

	char *file_in = argv[1];
	char *file_out = argv[2];

	int bytes = 256 * 256 * sizeof(int);
	unsigned int *points = (unsigned int *)calloc(1, bytes);

	FILE *fhi = fopen(file_in, "rb");
	if (!fhi)
	{
		fprintf(stderr, "Failed to open %s\n", file_in);
		return 1;
	}

	FILE *fho = fopen(file_out, "wb");
	if (!fho)
	{
		fprintf(stderr, "Failed to create %s\n", file_out);
		return 1;
	}

	while(!feof(fhi))
	{
		int x = fgetc(fhi);
		int y = fgetc(fhi);

		if (x < 0 || y < 0) // EOF probably
			break;

		points[y * 256 + x]++;
	}

	fclose(fhi);

	unsigned int c_max = 0, c_min = 1 << 31;
	for(int index=0; index<(256*256); index++)
	{
		if (points[index] > c_max)
			c_max = points[index];
		if (points[index] < c_min)
			c_min = points[index];
	}
	double div = double(c_max) - double(c_min);

	bytes = 256 * 256 * 3;
	unsigned char *result = (unsigned char *)calloc(1, bytes);

	for(int y=0; y<256; y++)
	{
		for(int x=0; x<256; x++)
		{
			if (points[y * 256 + x] == 0)
				continue;

			double val = double(points[y * 256 + x] - c_min) / div;

			result[y * 256 * 3 + x * 3 + 0] = result[y * 256 * 3 + x * 3 + 2] = 0;
			result[y * 256 * 3 + x * 3 + 1] = (unsigned char)maxval(minval(255.0, val * 255.0), 0.0);
		}
	}

	png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);

	png_infop info_ptr = png_create_info_struct(png_ptr);

	png_set_IHDR (png_ptr, info_ptr, 256, 256, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_DEFAULT, PNG_FILTER_TYPE_DEFAULT);

	unsigned char *row_pointers[256];
	for(int y=0; y<256; y++)
		row_pointers[y] = &result[y * 256 * 3];

	png_init_io(png_ptr, fho);
	png_set_rows(png_ptr, info_ptr, row_pointers);
	png_write_png(png_ptr, info_ptr, PNG_TRANSFORM_IDENTITY, NULL);

	fclose(fho);

	return 0;
}
