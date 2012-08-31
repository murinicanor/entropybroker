#include <stdio.h>
#include <stdlib.h>

static __inline__ unsigned long long GetCC(void)
{
  unsigned a, d; 
  asm volatile("rdtsc" : "=a" (a), "=d" (d)); 
  return ((unsigned long long)a) | (((unsigned long long)d) << 32LL); 
}

#define FIDDLE_N (1024 * 1024)

typedef struct
{
	char *buffer;
	int index;
} fiddle_state_t;

void fiddle(fiddle_state_t *p)
{
	// trigger cache misses etc
	(p -> buffer)[p -> index++]++;

	if (p -> index == FIDDLE_N)
		p -> index = 0;
}

int main(int argc, char *argv[])
{
	fiddle_state_t fs;

	fs.buffer = (char *)malloc(FIDDLE_N);
	fs.index = 0;

	unsigned char byte = 0;
	int bits = 0;

	for(;;)
	{
		unsigned long long int a = GetCC();
		fiddle(&fs);
		unsigned long long int b = GetCC();
		fiddle(&fs);
		unsigned long long int c = GetCC();
		fiddle(&fs);
		unsigned long long int d = GetCC();
		fiddle(&fs);

		int A = (int)(b - a);
		int B = (int)(d - c);

		if (A == B)
			continue;

		byte <<= 1;

		if (A > B)
			byte |= 1;
			
		bits++;

		if (bits == 8)
		{
			printf("%c", byte);
			bits = 0;
		}
	}

	return 0;
}
