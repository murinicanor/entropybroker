// SVN: $Revision$
#include <openssl/blowfish.h>

#include "encrypt_stream.h"
#include "encrypt_stream_blowfish.h"

encrypt_stream_blowfish::encrypt_stream_blowfish(unsigned char *key_in, int key_len, unsigned char ivec[8]) : encrypt_stream(ivec)
{
	BF_set_key(&key, key_len, key_in);
}

void encrypt_stream_blowfish::encrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
	BF_cfb64_encrypt(p, p_out, len, &key, ivec, &ivec_offset, BF_ENCRYPT);
}

void encrypt_stream_blowfish::decrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
	BF_cfb64_encrypt(p, p_out, len, &key, ivec, &ivec_offset, BF_DECRYPT);
}

std::string encrypt_stream_blowfish::get_name()
{
	return "blowfish";
}
