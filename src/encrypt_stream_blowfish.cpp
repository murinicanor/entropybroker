#include <string>
#include <vector>
#include <string.h>
#include <stdio.h>

#include "encrypt_stream.h"
#include "encrypt_stream_blowfish.h"
#include "utils.h"

encrypt_stream_blowfish::encrypt_stream_blowfish()
{
	enc = NULL;
	dec = NULL;
}

encrypt_stream_blowfish::~encrypt_stream_blowfish()
{
	delete enc;
	delete dec;
}

int encrypt_stream_blowfish::get_ivec_size()
{
	return CryptoPP::Blowfish::BLOCKSIZE;
}

int encrypt_stream_blowfish::get_key_size()
{
	return CryptoPP::Blowfish::DEFAULT_KEYLENGTH;
}

bool encrypt_stream_blowfish::init(unsigned char *key_in, int key_len, unsigned char *ivec_in, bool force)
{
	my_assert(key_len > 0);

#ifdef CRYPTO_DEBUG
	printf("KEY: "); hexdump(key_in, key_len);
#endif

	if (enc)
		delete enc;
	if (dec)
		delete dec;

	enc = new CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Encryption(key_in, key_len, ivec_in);
	dec = new CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Decryption(key_in, key_len, ivec_in);

	return true;
}

std::string encrypt_stream_blowfish::get_name()
{
	return "blowfish";
}

void encrypt_stream_blowfish::encrypt(unsigned char *p, int len, unsigned char *p_out)
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

void encrypt_stream_blowfish::decrypt(unsigned char *p, int len, unsigned char *p_out)
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
