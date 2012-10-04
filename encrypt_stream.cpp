// SVN: $Revision$
#include "encrypt_stream.h"
#include "encrypt_stream_blowfish.h"

encrypt_stream::encrypt_stream(unsigned char ivec_in[8])
{
	memcpy(ivec, ivec_in, sizeof ivec);

	ivec_offset = 0;
}

encrypt_stream * encrypt_stream::select_cipher(std::string type, unsigned char *key, int key_len, unsigned char ivec[8])
{
	if (type == "blowfish")
		return new encrypt_stream_blowfish(key, key_len, ivec);

	return NULL;
}
