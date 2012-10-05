// SVN: $Revision$
#include <string>
#include <openssl/sha.h>

#include "hasher.h"
#include "hasher_sha512.h"

hasher_sha512::hasher_sha512()
{
}

hasher_sha512::~hasher_sha512()
{
}

std::string hasher_sha512::get_name()
{
	return "sha512";
}

int hasher_sha512::get_hash_size() const
{
	return SHA512_DIGEST_LENGTH;
}

void hasher_sha512::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	SHA512(in, in_size, dest);
}
