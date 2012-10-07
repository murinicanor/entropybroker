// SVN: $Revision$
#include <string>
#include <string.h>
#include "encrypt_stream.h"
#include "encrypt_stream_3des.h"
#include "utils.h"

encrypt_stream_3des::encrypt_stream_3des() : ivec_offset(0)
{
}

int encrypt_stream_3des::get_ivec_size()
{
	return 8;
}

int encrypt_stream_3des::get_key_size()
{
	return 8 * 3;
}

bool encrypt_stream_3des::init(unsigned char *key_in, int key_len, unsigned char *ivec_in, bool force)
{
#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
	printf("IVEC STRT: "); hexdump(ivec_in, 8);
#endif

	DES_cblock dk;

	char temp_key[24] = { 0 };
	memcpy(temp_key, key_in, key_len);

	memcpy(dk, &temp_key[0], 8);
	DES_set_odd_parity(&dk);
	if (DES_is_weak_key(&dk) == 1 && !force)
		return false;
	DES_set_key_unchecked(&dk, &ks1);

	memcpy(dk, &temp_key[8], 8);
	DES_set_odd_parity(&dk);
	if (DES_is_weak_key(&dk) == 1 && !force)
		return false;
	DES_set_key_unchecked(&dk, &ks2);

	memcpy(dk, &temp_key[16], 8);
	DES_set_odd_parity(&dk);
	if (DES_is_weak_key(&dk) == 1 && !force)
		return false;
	DES_set_key_unchecked(&dk, &ks3);

	memcpy(iv, ivec_in, 8);
#ifdef CRYPTO_DEBUG
	printf("IVEC STRT2: "); hexdump(iv, 8);
#endif

	return true;
}

void encrypt_stream_3des::encrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("ORG: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(iv, 8);
#endif

	DES_ede3_cfb64_encrypt(p, p_out, len, &ks1, &ks2, &ks3, &iv, &ivec_offset, DES_ENCRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(iv, 8);
	printf("ENC: "); hexdump(p_out, len);
#endif
}

void encrypt_stream_3des::decrypt(unsigned char *p, size_t len, unsigned char *p_out)
{
#ifdef CRYPTO_DEBUG
	printf("DEC: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(iv, 8);
#endif

	DES_ede3_cfb64_encrypt(p, p_out, len, &ks1, &ks2, &ks3, &iv, &ivec_offset, DES_DECRYPT);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(iv, 8);
	printf("ORG: "); hexdump(p_out, len);
#endif
}

std::string encrypt_stream_3des::get_name()
{
	return "3des";
}
