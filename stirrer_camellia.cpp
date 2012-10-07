// SVN: $Revision$
#include <string.h>
#include <arpa/inet.h>
#include <string>
#include <openssl/camellia.h>

#include "error.h"
#include "utils.h"
#include "encrypt_stream.h"
#include "encrypt_stream_camellia.h"
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
	return enc.get_key_size();
}

int stirrer_camellia::get_ivec_size()
{
	return enc.get_ivec_size();;
}

void stirrer_camellia::do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction)
{
	if (data_in_size > get_stir_size())
		error_exit("Invalid stir-size %d (expected: %d)", data_in_size, get_stir_size());

	enc.init(data_in, data_in_size, ivec, true);

	enc.encrypt(target, target_size, temp_buffer);
	memcpy(target, temp_buffer, target_size);
}
