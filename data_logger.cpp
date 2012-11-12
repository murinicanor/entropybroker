#include <pthread.h>
#include <string>
#include <unistd.h>

#include "utils.h"
#include "error.h"
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

data_logger::data_logger(pools *ppools_in, std::vector<client_t *> *clients_in, pthread_mutex_t *clients_mutex_in) : ppools(ppools_in), clients(clients_in), clients_mutex(clients_mutex_in)
{
	abort = false;

	if (file_exist(MEM_POOL_COUNTS))
		mem_pool_counts = new data_store_int(MEM_POOL_COUNTS);
	else
		mem_pool_counts = new data_store_int(1440 * 7, 300);
	pthread_check(pthread_mutex_init(&mem_pool_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(DSK_POOL_COUNTS))
		dsk_pool_counts = new data_store_int(DSK_POOL_COUNTS);
	else
		dsk_pool_counts = new data_store_int(1440 * 7, 300);
	pthread_check(pthread_mutex_init(&dsk_pool_lck, &global_mutex_attr), "pthread_mutex_init");

	if (file_exist(CONNECTION_COUNTS))
		connection_counts = new data_store_int(CONNECTION_COUNTS);
	else
		connection_counts = new data_store_int(1440 * 7, 300);
	pthread_check(pthread_mutex_init(&connection_counts_lck, &global_mutex_attr), "pthread_mutex_init");

	pthread_check(pthread_create(&thread, NULL, start_data_logger_thread_wrapper, this), "pthread_create");
}

data_logger::~data_logger()
{
	abort = true;
	pthread_check(pthread_join(thread, NULL), "pthread_join");

	mem_pool_counts -> dump(MEM_POOL_COUNTS);
	delete mem_pool_counts;
	pthread_check(pthread_mutex_destroy(&mem_pool_lck), "pthread_mutex_destroy");

	dsk_pool_counts -> dump(DSK_POOL_COUNTS);
	delete dsk_pool_counts;
	pthread_check(pthread_mutex_destroy(&dsk_pool_lck), "pthread_mutex_destroy");

	connection_counts -> dump(CONNECTION_COUNTS);
	delete connection_counts;
	pthread_check(pthread_mutex_destroy(&connection_counts_lck), "pthread_mutex_destroy");
}

void data_logger::run()
{
	double prev_ts = -1;

	for(; !abort;)
	{
		double now_ts = get_ts();

		if (now_ts - prev_ts >= 300.0)
		{
			// FIXME
			my_mutex_lock(&mem_pool_lck);
			mem_pool_counts -> add_avg(time_t(now_ts), ppools -> get_memory_pool_count());
			my_mutex_unlock(&mem_pool_lck);

			my_mutex_lock(&dsk_pool_lck);
			dsk_pool_counts -> add_avg(time_t(now_ts), ppools -> get_disk_pool_count());
			my_mutex_unlock(&dsk_pool_lck);

			my_mutex_lock(clients_mutex);
			connection_counts -> add_avg(time_t(now_ts), clients -> size());
			my_mutex_unlock(clients_mutex);

			prev_ts = now_ts;
		}

		sleep(1);
	}
}
