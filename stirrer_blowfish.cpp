// SVN: $Revision$
#include <string.h>
#include <arpa/inet.h>
#include <string>
#include <arpa/inet.h>
#include <openssl/blowfish.h>

#include "error.h"
#include "utils.h"
#include "encrypt_stream.h"
#include "encrypt_stream_blowfish.h"
#include "stirrer.h"
#include "stirrer_blowfish.h"

stirrer_blowfish::stirrer_blowfish()
{
}

stirrer_blowfish::~stirrer_blowfish()
{
}

int stirrer_blowfish::get_stir_size()
{
	return enc.get_key_size();
}

int stirrer_blowfish::get_ivec_size()
{
	return enc.get_ivec_size();
}

void stirrer_blowfish::do_stir(unsigned char *ivec, unsigned char *target, int target_size, unsigned char *data_in, int data_in_size, unsigned char *temp_buffer, bool direction)
{
	if (data_in_size > get_stir_size())
		error_exit("Invalid stir-size %d (expected: %d)", data_in_size, get_stir_size());

	enc.init(data_in, data_in_size, ivec, true);

	enc.encrypt(target, target_size, temp_buffer);

	memcpy(target, temp_buffer, target_size);
}
