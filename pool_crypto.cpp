#include <string>

#include "error.h"
#include "encrypt_stream.h"
#include "encrypt_stream_3des.h"
#include "encrypt_stream_aes.h"
#include "encrypt_stream_blowfish.h"
#include "encrypt_stream_camellia.h"
#include "stirrer_type.h"
#include "stirrer.h"
#include "stirrer_3des.h"
#include "stirrer_aes.h"
#include "stirrer_blowfish.h"
#include "stirrer_camellia.h"
#include "hasher_type.h"
#include "hasher.h"
#include "hasher_md5.h"
#include "hasher_ripemd160.h"
#include "hasher_sha512.h"
#include "hasher_whirlpool.h"
#include "random_source.h"
#include "pool_crypto.h"

pool_crypto::pool_crypto(stirrer_type st, hasher_type ht, random_source_t rst)
{
	if (ht == H_SHA512)
		h = new hasher_sha512();
	else if (ht == H_MD5)
		h = new hasher_md5();
	else if (ht == H_RIPEMD160)
		h = new hasher_ripemd160();
	else if (ht == H_WHIRLPOOL)
		h = new hasher_whirlpool();
	else
		error_exit("Internal error: no hasher (%d)", ht);

	if (st == S_BLOWFISH)
		s = new stirrer_blowfish();
	else if (st == S_AES)
		s = new stirrer_aes();
	else if (st == S_3DES)
		s = new stirrer_3des();
	else if (st == S_CAMELLIA)
		s = new stirrer_camellia();
	else
		error_exit("Internal error: no stirrer (%d)", st);

	rs = new random_source(rst);
}

pool_crypto::~pool_crypto()
{
	delete s;
	delete h;
	delete rs;
}
