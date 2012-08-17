#include <openssl/ripemd.h>

#include "hasher.h"
#include "hasher_ripemd160.h"

hasher_ripemd160::hasher_ripemd160()
{
}

hasher_ripemd160::~hasher_ripemd160()
{
}

int hasher_ripemd160::get_hash_size() const
{
	return RIPEMD160_DIGEST_LENGTH;
}

void hasher_ripemd160::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	RIPEMD160(in, in_size, dest);
}
