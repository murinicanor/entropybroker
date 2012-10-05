// SVN: $Revision$
#include <string.h>
#include <string>
#include <openssl/blowfish.h>

#include "encrypt_stream.h"
#include "encrypt_stream_blowfish.h"

encrypt_stream::encrypt_stream()
{
	ivec_offset = 0;
}

encrypt_stream::~encrypt_stream()
{
}

encrypt_stream * encrypt_stream::select_cipher(std::string type)
{
	if (type == "blowfish")
		return new encrypt_stream_blowfish();

	return NULL;
}

void encrypt_stream::init(unsigned char *key_in, int key_len, unsigned char ivec_in[8])
{
	memcpy(ivec, ivec_in, sizeof ivec);
}
