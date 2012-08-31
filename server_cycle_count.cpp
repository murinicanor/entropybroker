#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

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
	int a = (p -> buffer)[p -> index++]++;

	if (p -> index == FIDDLE_N)
		p -> index = 0;

	// trigger an occasional exception
	a /= (p -> buffer)[p -> index];
}

int main(int argc, char *argv[])
{
	fiddle_state_t fs;

	fs.buffer = (char *)malloc(FIDDLE_N);
	fs.index = 0;

	signal(SIGFPE, SIG_IGN);
	signal(SIGSEGV, SIG_IGN);

	unsigned char byte = 0;
	int bits = 0;

	for(;;)
	{
		fiddle(&fs);
		unsigned long long int a = GetCC();
		fiddle(&fs);
		unsigned long long int b = GetCC();
		fiddle(&fs);
		unsigned long long int c = GetCC();
		fiddle(&fs);
		unsigned long long int d = GetCC();

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
