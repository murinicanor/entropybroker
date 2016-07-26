#include <string>
#include <vector>
#include <string.h>
#include "encrypt_stream.h"
#include "encrypt_stream_3des.h"
#include "utils.h"

encrypt_stream_3des::encrypt_stream_3des()
{
	enc = NULL;
	dec = NULL;
}

encrypt_stream_3des::~encrypt_stream_3des()
{
	delete enc;
	delete dec;
}

int encrypt_stream_3des::get_ivec_size()
{
	return CryptoPP::DES_EDE3::BLOCKSIZE;
}

int encrypt_stream_3des::get_key_size()
{
	return CryptoPP::DES_EDE3::DEFAULT_KEYLENGTH;
}

bool encrypt_stream_3des::init(unsigned char *key_in, int key_len, unsigned char *ivec_in, bool force)
{
	my_assert(key_len > 0);

#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
	printf("IVEC STRT: "); hexdump(ivec_in, 8);
#endif

	if (enc)
		delete enc;
	if (dec)
		delete dec;

	unsigned char dummy[24] = { 0 };
	memcpy(dummy, key_in, std::min(int(sizeof dummy), key_len));

	enc = new CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Encryption(dummy, sizeof dummy, ivec_in);
	dec = new CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Decryption(dummy, sizeof dummy, ivec_in);

	return true;
}

std::string encrypt_stream_3des::get_name()
{
	return "3des";
}

void encrypt_stream_3des::encrypt(unsigned char *p, int len, unsigned char *p_out)
{
	my_assert(len > 0);

#ifdef CRYPTO_DEBUG
	printf("ORG: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	enc -> ProcessData(p_out, p, len);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ENC: "); hexdump(p_out, len);
#endif
}

void encrypt_stream_3des::decrypt(unsigned char *p, int len, unsigned char *p_out)
{
	my_assert(len > 0);

#ifdef CRYPTO_DEBUG
	printf("DEC: "); hexdump(p, len);
	printf("EIV %d before: ", ivec_offset); hexdump(ivec, 8);
#endif

	dec -> ProcessData(p_out, p, len);

#ifdef CRYPTO_DEBUG
	printf("EIV %d after: ", ivec_offset); hexdump(ivec, 8);
	printf("ORG: "); hexdump(p_out, len);
#endif
}
