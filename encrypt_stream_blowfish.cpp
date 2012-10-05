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

int encrypt_stream_blowfish::get_ivec_size()
{
	return BF_BLOCK;
}

void encrypt_stream_blowfish::init(unsigned char *key_in, int key_len, unsigned char *ivec_in)
{
#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
#endif

	memcpy(ivec, ivec_in, sizeof ivec);

	BF_set_key(&key, key_len, key_in);
}

void encrypt_stream_blowfish::encrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("ORG: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	BF_cfb64_encrypt(p, p_out, len, &key, ivec, &ivec_offset, BF_ENCRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ENC: "); hexdump(p_out, len);
#endif
}

void encrypt_stream_blowfish::decrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("DEC: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	BF_cfb64_encrypt(p, p_out, len, &key, ivec, &ivec_offset, BF_DECRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ORG: "); hexdump(p_out, len);
#endif
}

std::string encrypt_stream_blowfish::get_name()
{
	return "blowfish";
}
