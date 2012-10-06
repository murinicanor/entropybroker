// SVN: $Revision$
#include <string.h>
#include <arpa/inet.h>
#include <string>
#include <openssl/camellia.h>

#include "error.h"
#include "utils.h"
#include "stirrer.h"
#include "stirrer_camellia.h"

stirrer_camellia::stirrer_camellia()
{
}

stirrer_camellia::~stirrer_camellia()
{
}

int stirrer_camellia::get_stir_size()
{
	return 256 / 8;
}

int stirrer_camellia::get_ivec_size()
{
	return CAMELLIA_BLOCK_SIZE;
}

void stirrer_camellia::do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction)
{
	unsigned char temp_key[32] = { 0 };

	if (data_in_size > get_stir_size())
		error_exit("Invalid stir-size %d (expected: %d)", data_in_size, get_stir_size());

	memcpy(temp_key, data_in, data_in_size);

	CAMELLIA_KEY key;
	Camellia_set_key(temp_key, 32 * 8, &key);

	int ivec_offset = 0;
	Camellia_cfb8_encrypt(target, temp_buffer, target_size, &key, ivec, &ivec_offset, direction ? CAMELLIA_ENCRYPT : CAMELLIA_DECRYPT);
	memcpy(target, temp_buffer, target_size);
}
