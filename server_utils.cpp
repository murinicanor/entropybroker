#include <stdio.h>

#include "error.h"

void emit_buffer_to_file(char *file, unsigned char *data, size_t n_bytes)
{
	FILE *fh = fopen(file, "a+");
	if (!fh)
		error_exit("Error opening %s for append access", file);

	if (fwrite(data, 1, n_bytes, fh) != n_bytes)
		error_exit("Short write to %s", file);

	fclose(fh);
}
