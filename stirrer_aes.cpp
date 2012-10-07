// SVN: $Revision$
#include <string.h>
#include <arpa/inet.h>
#include <string>

#include "error.h"
#include "utils.h"
#include "encrypt_stream.h"
#include "encrypt_stream_aes.h"
#include "stirrer.h"
#include "stirrer_aes.h"

stirrer_aes::stirrer_aes()
{
}

stirrer_aes::~stirrer_aes()
{
}

int stirrer_aes::get_stir_size()
{
	return enc.get_key_size();
}

int stirrer_aes::get_ivec_size()
{
	return enc.get_ivec_size();
}

void stirrer_aes::do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction)
{
	unsigned char temp_key[32] = { 0 };

	if (data_in_size > get_stir_size())
		error_exit("Invalid stir-size %d (expected: %d)", data_in_size, get_stir_size());

	memcpy(temp_key, data_in, data_in_size);

	enc.init(temp_key, 32, ivec, true);

	enc.encrypt(target, target_size, temp_buffer);

	memcpy(target, temp_buffer, target_size);
}
