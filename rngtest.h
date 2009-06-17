typedef struct
{
	int monobit;
	int poker;
	int longrun;
	int runs;
} rngtest_stats_t;

void RNGTEST_init(rngtest_stats_t *rtst);
void RNGTEST_add(unsigned char newval);
char RNGTEST_shorttest(void);
char RNGTEST_longtest(void);
char RNGTEST(void);
char *RNGTEST_stats(void);
