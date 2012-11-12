typedef struct
{
	char r, g, b;
} pixel;

bool encode_png(pixel **img, int width, int height, char **result, size_t *result_len);
