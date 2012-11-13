#include <pthread.h>
#include <string>
#include <unistd.h>

#include "defines.h"
#include "error.h"
#include "utils.h"
#include "log.h"
#include "utils.h"
#include "hasher.h"
#include "math.h"
#include "stirrer.h"
#include "random_source.h"
#include "fips140.h"
#include "scc.h"
#include "hasher_type.h"
#include "stirrer_type.h"
#include "pool_crypto.h"
#include "pool.h"
#include "pools.h"
#include "config.h"
#include "encrypt_stream.h"
#include "statistics.h"
#include "users.h"
#include "handle_client.h"
#include "data_store_int.h"
#include "data_logger.h"

void *start_data_logger_thread_wrapper(void *p)
{
	data_logger *dl = reinterpret_cast<data_logger *>(p);

	dl -> run();

	return NULL;
}

data_logger::data_logger(statistics *s_in, pools *ppools_in, std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in) : s(s_in), ppools(ppools_in), clients(clients_in), clients_mutex(clients_mutex_in)
{
	abort = false;

	pthread_check(pthread_mutex_init(&terminate_flag_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(MEM_POOL_COUNTS))
		mem_pool_counts = new data_store_int(MEM_POOL_COUNTS);
	else
		mem_pool_counts = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&mem_pool_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(DSK_POOL_COUNTS))
		dsk_pool_counts = new data_store_int(DSK_POOL_COUNTS);
	else
		dsk_pool_counts = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&dsk_pool_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(CONNECTION_COUNTS))
		connection_counts = new data_store_int(CONNECTION_COUNTS);
	else
		connection_counts = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&connection_counts_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(MEM_POOL_BIT_COUNT_COUNTS))
		mem_pool_bit_count_counts = new data_store_int(MEM_POOL_BIT_COUNT_COUNTS);
	else
		mem_pool_bit_count_counts = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&mem_pool_bit_count_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(DSK_POOL_BIT_COUNT_COUNTS))
		dsk_pool_bit_count_counts = new data_store_int(DSK_POOL_BIT_COUNT_COUNTS);
	else
		dsk_pool_bit_count_counts = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&dsk_pool_bit_count_lck, &global_mutex_attr), "pthread_mutex_init");

	prev_recv_n = prev_sent_n = -1;

	if (file_exist(RECV_BIT_COUNT))
		recv_bit_count = new data_store_int(RECV_BIT_COUNT);
	else
		recv_bit_count = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&recv_bit_count_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(SENT_BIT_COUNT))
		sent_bit_count = new data_store_int(SENT_BIT_COUNT);
	else
		sent_bit_count = new data_store_int(MEASURE_KEEP_N, MEASURE_INTERVAL);
	pthread_check(pthread_mutex_init(&sent_bit_count_lck, &global_mutex_attr), "pthread_mutex_init");

	pthread_check(pthread_create(&thread, NULL, start_data_logger_thread_wrapper, this), "pthread_create");
}

data_logger::~data_logger()
{
	my_mutex_lock(&terminate_flag_lck);
	abort = true;
	my_mutex_unlock(&terminate_flag_lck);

	dolog(LOG_INFO, "data logger about to terminate: waiting to thread to terminate");

	pthread_check(pthread_join(thread, NULL), "pthread_join");

	dolog(LOG_INFO, "data logger thread stopped");

	pthread_check(pthread_mutex_destroy(&terminate_flag_lck), "pthread_mutex_destroy");

	dump_data();

	delete mem_pool_counts;
	pthread_check(pthread_mutex_destroy(&mem_pool_lck), "pthread_mutex_destroy");

	delete dsk_pool_counts;
	pthread_check(pthread_mutex_destroy(&dsk_pool_lck), "pthread_mutex_destroy");

	delete connection_counts;
	pthread_check(pthread_mutex_destroy(&connection_counts_lck), "pthread_mutex_destroy");

	delete mem_pool_bit_count_counts;
	pthread_check(pthread_mutex_destroy(&mem_pool_bit_count_lck), "pthread_mutex_destroy");

	delete dsk_pool_bit_count_counts;
	pthread_check(pthread_mutex_destroy(&dsk_pool_bit_count_lck), "pthread_mutex_destroy");

	delete recv_bit_count;
	pthread_check(pthread_mutex_destroy(&recv_bit_count_lck), "pthread_mutex_destroy");

	delete sent_bit_count;
	pthread_check(pthread_mutex_destroy(&sent_bit_count_lck), "pthread_mutex_destroy");

	dolog(LOG_INFO, "data logger stopped");
}

void data_logger::dump_data()
{
	dolog(LOG_INFO, "dump statistics to disk");

	my_mutex_lock(&mem_pool_lck);
	mem_pool_counts -> dump(MEM_POOL_COUNTS);
	my_mutex_unlock(&mem_pool_lck);

	my_mutex_lock(&dsk_pool_lck);
	dsk_pool_counts -> dump(DSK_POOL_COUNTS);
	my_mutex_unlock(&dsk_pool_lck);

	my_mutex_lock(&connection_counts_lck);
	connection_counts -> dump(CONNECTION_COUNTS);
	my_mutex_unlock(&connection_counts_lck);

	my_mutex_lock(&mem_pool_bit_count_lck);
	mem_pool_bit_count_counts -> dump(MEM_POOL_BIT_COUNT_COUNTS);
	my_mutex_unlock(&mem_pool_bit_count_lck);

	my_mutex_lock(&dsk_pool_bit_count_lck);
	dsk_pool_bit_count_counts -> dump(DSK_POOL_BIT_COUNT_COUNTS);
	my_mutex_unlock(&dsk_pool_bit_count_lck);

	my_mutex_lock(&sent_bit_count_lck);
	sent_bit_count -> dump(SENT_BIT_COUNT);
	my_mutex_unlock(&sent_bit_count_lck);

	my_mutex_lock(&recv_bit_count_lck);
	recv_bit_count -> dump(RECV_BIT_COUNT);
	my_mutex_unlock(&recv_bit_count_lck);
}

void data_logger::run()
{
	double prev_ts = -1, last_dump_ts = get_ts();

	for(;;)
	{
		my_mutex_lock(&terminate_flag_lck);
		bool terminate = abort;
		my_mutex_unlock(&terminate_flag_lck);

		if (terminate)
			break;

		double now_ts = get_ts();

		if (now_ts - prev_ts >= MEASURE_INTERVAL)
		{
			time_t dummy_ts = time_t(now_ts);

			my_mutex_lock(&mem_pool_lck);
			mem_pool_counts -> add_avg(dummy_ts, ppools -> get_memory_pool_count());
			my_mutex_unlock(&mem_pool_lck);

			my_mutex_lock(&dsk_pool_lck);
			dsk_pool_counts -> add_avg(dummy_ts, ppools -> get_disk_pool_count());
			my_mutex_unlock(&dsk_pool_lck);

			my_mutex_lock(&connection_counts_lck);
			connection_counts -> add_avg(dummy_ts, clients -> size());
			my_mutex_unlock(&connection_counts_lck);

			my_mutex_lock(&mem_pool_bit_count_lck);
			mem_pool_bit_count_counts -> add_avg(dummy_ts, ppools -> get_bit_sum(DEFAULT_COMM_TO + 1.0));
			my_mutex_unlock(&mem_pool_bit_count_lck);

			my_mutex_lock(&dsk_pool_bit_count_lck);
			dsk_pool_bit_count_counts -> add_avg(dummy_ts, ppools -> get_disk_pool_bit_count());
			my_mutex_unlock(&dsk_pool_bit_count_lck);

			long long int recv_total_bits = 0, sent_total_bits = 0;
			int n_reqs = 0, n_sents = 0;
			s -> get_recvs(&recv_total_bits, &n_reqs);
			s -> get_sents(&sent_total_bits, &n_sents);

			if (prev_recv_n != -1)
			{
				my_mutex_lock(&recv_bit_count_lck);
				recv_bit_count -> add_avg(dummy_ts, recv_total_bits - prev_recv_n);
				my_mutex_unlock(&recv_bit_count_lck);
			}
			prev_recv_n = recv_total_bits;

			if (prev_sent_n != -1)
			{
				my_mutex_lock(&sent_bit_count_lck);
				sent_bit_count -> add_avg(dummy_ts, sent_total_bits - prev_sent_n);
				my_mutex_unlock(&sent_bit_count_lck);
			}
			prev_sent_n = sent_total_bits;

			prev_ts = now_ts;
		}

		if (now_ts - last_dump_ts >= 86400) // push to disk once a day
		{
			dump_data();

			last_dump_ts = now_ts;
		}

		sleep(1);
	}
}

void data_logger::get_mem_pool_counts(long int **t, double **v, int *n)
{
	my_mutex_lock(&mem_pool_lck);
	mem_pool_counts -> get_data(t, v, n);
	my_mutex_unlock(&mem_pool_lck);
}

void data_logger::get_dsk_pool_counts(long int **t, double **v, int *n)
{
	my_mutex_lock(&dsk_pool_lck);
	dsk_pool_counts -> get_data(t, v, n);
	my_mutex_unlock(&dsk_pool_lck);
}

void data_logger::get_connection_counts(long int **t, double **v, int *n)
{
	my_mutex_lock(clients_mutex);
	connection_counts -> get_data(t, v, n);
	my_mutex_unlock(clients_mutex);
}

void data_logger::get_pools_bitcounts(long int **t, double **v, int *n)
{
	my_mutex_lock(&mem_pool_bit_count_lck);
	mem_pool_bit_count_counts -> get_data(t, v, n);
	my_mutex_unlock(&mem_pool_bit_count_lck);
}

void data_logger::get_disk_pools_bitcounts(long int **t, double **v, int *n)
{
	my_mutex_lock(&dsk_pool_bit_count_lck);
	dsk_pool_bit_count_counts -> get_data(t, v, n);
	my_mutex_unlock(&dsk_pool_bit_count_lck);
}

void data_logger::get_recv_bit_count(long int **t, double **v, int *n)
{
	my_mutex_lock(&recv_bit_count_lck);
	recv_bit_count -> get_data(t, v, n);
	my_mutex_unlock(&recv_bit_count_lck);
}

void data_logger::get_sent_bit_count(long int **t, double **v, int *n)
{
	my_mutex_lock(&sent_bit_count_lck);
	sent_bit_count -> get_data(t, v, n);
	my_mutex_unlock(&sent_bit_count_lck);
}
