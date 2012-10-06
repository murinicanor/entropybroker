// SVN: $Revision$
#include <string>
#include <string.h>
#include <stdio.h>

#include "encrypt_stream.h"
#include "encrypt_stream_aes.h"
#include "utils.h"

encrypt_stream_aes::encrypt_stream_aes()
{
}

int encrypt_stream_aes::get_ivec_size()
{
	return AES_BLOCK_SIZE;
}

int encrypt_stream_aes::get_key_size()
{
	return 256 / 8;
}

bool encrypt_stream_aes::init(unsigned char *key_in, int key_len, unsigned char *ivec_in)
{
#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
#endif

	memcpy(ivec, ivec_in, sizeof ivec);

	unsigned char key_use[32] = { 0 };
	memcpy(key_use, key_in, min(32, key_len));

	AES_set_encrypt_key(key_use, 32 * 8, &key_enc);
	AES_set_encrypt_key(key_use, 32 * 8, &key_dec); // due to the cfb used

	return true;
}

void encrypt_stream_aes::encrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("ORG: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	AES_cfb128_encrypt(p, p_out, len, &key_enc, ivec, &ivec_offset, AES_ENCRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ENC: "); hexdump(p_out, len);
#endif
}

void encrypt_stream_aes::decrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("DEC: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	AES_cfb128_encrypt(p, p_out, len, &key_dec, ivec, &ivec_offset, AES_DECRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ORG: "); hexdump(p_out, len);
#endif
}

std::string encrypt_stream_aes::get_name()
{
	return "aes";
}
