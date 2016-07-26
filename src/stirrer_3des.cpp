#include <string.h>
#include <arpa/inet.h>
#include <string>
#include <vector>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "encrypt_stream.h"
#include "encrypt_stream_3des.h"
#include "stirrer.h"
#include "stirrer_3des.h"

stirrer_3des::stirrer_3des()
{
}

stirrer_3des::~stirrer_3des()
{
}

int stirrer_3des::get_stir_size()
{
	return enc.get_key_size();
}

int stirrer_3des::get_ivec_size()
{
	return enc.get_ivec_size();
}

void stirrer_3des::do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction)
{
	my_assert(target_size > 0);
	my_assert(data_in_size > 0);

	unsigned char temp_key[24] = { 0 };

	if (data_in_size > get_stir_size())
		error_exit("Invalid stir-size %d (expected: %d)", data_in_size, get_stir_size());

	memcpy(temp_key, data_in, data_in_size);

	enc.init(temp_key, 24, ivec, true);

	enc.encrypt(target, target_size, temp_buffer);
	memcpy(target, temp_buffer, target_size);
}
