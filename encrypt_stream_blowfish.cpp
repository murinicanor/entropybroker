// SVN: $Revision$
#include <string>
#include <string.h>
#include <stdio.h>

#include "encrypt_stream.h"
#include "encrypt_stream_blowfish.h"
#include "utils.h"

encrypt_stream_blowfish::encrypt_stream_blowfish()
{
}

void encrypt_stream_blowfish::init(unsigned char *key_in, int key_len, unsigned char ivec_in[8])
{
	// printf("KEY: "); hexdump(key_in, key_len);

	memcpy(ivec, ivec_in, sizeof ivec);

	BF_set_key(&key, key_len, key_in);
}

void encrypt_stream_blowfish::encrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
	// printf("ORG: "); hexdump(p, len);
	// printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
	BF_cfb64_encrypt(p, p_out, len, &key, ivec, &ivec_offset, BF_ENCRYPT);
	// printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	// printf("ENC: "); hexdump(p_out, len);
}

void encrypt_stream_blowfish::decrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
	// printf("DEC: "); hexdump(p, len);
	// printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
	BF_cfb64_encrypt(p, p_out, len, &key, ivec, &ivec_offset, BF_DECRYPT);
	// printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	// printf("ORG: "); hexdump(p_out, len);
}

std::string encrypt_stream_blowfish::get_name()
{
	return "blowfish";
}
