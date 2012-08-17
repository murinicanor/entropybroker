#include <openssl/sha.h>

#include "hasher.h"

hasher::hasher()
{
}

hasher::~hasher()
{
}

int hasher::get_hash_size() const
{
	return SHA512_DIGEST_LENGTH;
}

void hasher::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	SHA512(in, in_size, dest);
}
