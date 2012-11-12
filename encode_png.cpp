#include <stdio.h>
#include <stdlib.h>
#include <png.h>

#include "log.h"
#include "encode_png.h"

bool encode_png(pixel **img, int width, int height, char **result, size_t *result_len)
{
	bool rc = false;

	*result = NULL;
	*result_len = 0;

	FILE * fh = NULL;

	for(;;)
	{
		fh = open_memstream(result, result_len);
		if (!fh)
		{
			dolog(LOG_WARNING, "encode_png: open_memstream failed");
			break;
		}

		png_structp png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
		if (!png_ptr)
		{
			dolog(LOG_INFO, "encode_png: png_create_write_struct failed");
			break;
		}

		png_infop info_ptr = png_create_info_struct(png_ptr);
		if (!info_ptr)
		{
			dolog(LOG_INFO, "encode_png: png_create_info_struct failed");
			break;
		}

		png_init_io(png_ptr, fh);

		png_set_IHDR(png_ptr, info_ptr, width, height, 8, PNG_COLOR_TYPE_RGB, PNG_INTERLACE_NONE, PNG_COMPRESSION_TYPE_BASE, PNG_FILTER_TYPE_BASE);

		png_write_info(png_ptr, info_ptr);

		png_bytep * row_pointers = (png_bytep *)malloc(height * sizeof(png_bytep));
		for(int y=0; y<height; y++)
		{
			row_pointers[y] = (png_bytep)malloc(width * 4);
			char *p = (char *)row_pointers[y];

			for(int x=0; x<width; x++)
			{
				*p++ = img[y][x].r;
				*p++ = img[y][x].g;
				*p++ = img[y][x].b;
			}
		}

		png_write_image(png_ptr, row_pointers);

		png_write_end(png_ptr, NULL);

		for(int y=0; y<height; y++)
			free(row_pointers[y]);
		free(row_pointers);

		rc = true;

		break;
	}

	if (fh)
		fclose(fh);

	if (!rc)
	{
		free(*result);
		*result = NULL;
	}

	return rc;
}
