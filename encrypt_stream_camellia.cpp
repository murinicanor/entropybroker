// SVN: $Revision$
#include <string>
#include <string.h>
#include <stdio.h>

#include "encrypt_stream.h"
#include "encrypt_stream_camellia.h"
#include "utils.h"

encrypt_stream_camellia::encrypt_stream_camellia() : ivec_offset(0)
{
}

int encrypt_stream_camellia::get_ivec_size()
{
	return CAMELLIA_BLOCK_SIZE;
}

int encrypt_stream_camellia::get_key_size()
{
	return 256/8;
}

bool encrypt_stream_camellia::init(unsigned char *key_in, int key_len, unsigned char *ivec_in)
{
#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
#endif

	memcpy(ivec, ivec_in, sizeof ivec);

	Camellia_set_key(key_in, key_len * 8, &key);

	return true;
}

void encrypt_stream_camellia::encrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("ORG: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	Camellia_cfb8_encrypt(p, p_out, len, &key, ivec, &ivec_offset, CAMELLIA_ENCRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ENC: "); hexdump(p_out, len);
#endif
}

void encrypt_stream_camellia::decrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("DEC: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	Camellia_cfb8_encrypt(p, p_out, len, &key, ivec, &ivec_offset, CAMELLIA_DECRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ORG: "); hexdump(p_out, len);
#endif
}

std::string encrypt_stream_camellia::get_name()
{
	return "camellia";
}
