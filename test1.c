#include <stdio.h>
#include <time.h>
#include <sys/time.h>

int main(int argc, char  *argv[])
{
	double avg = 0;
	char first = 1;
	int byte = 0, bits = 0;
	for(;;)
	{
		struct timeval tv;
		struct timespec crt, cm, cpcti;

		clock_gettime(CLOCK_REALTIME, &crt);
		clock_gettime(CLOCK_MONOTONIC, &cm);
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpcti);
		gettimeofday(&tv, NULL);

//		printf("%d %d %d\n", crt.tv_nsec - cm.tv_nsec, crt.tv_nsec - cpcti.tv_nsec, crt.tv_nsec - (tv.tv_usec * 1000));
		if (first)
		{
			avg = crt.tv_nsec - cm.tv_nsec;
			first = 0;
		}
		else
		{
			int value = (crt.tv_nsec - cm.tv_nsec) - (int)avg;
//			printf("%d %d %d %d\n", crt.tv_nsec, cm.tv_nsec, crt.tv_nsec - cm.tv_nsec, (crt.tv_nsec - cm.tv_nsec) - (int)avg);
			avg = (avg + (double)(crt.tv_nsec - cm.tv_nsec)) / 2.0;

			byte <<= 1;
			if (value > 0)
				byte |= 1;
			bits++;

			if (bits == 8)
			{
				printf("%c", byte);
				byte = bits = 0;
			}
		}

//		sleep(1);
	}

	return 0;
}
