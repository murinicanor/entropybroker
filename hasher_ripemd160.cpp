// SVN: $Revision$
#include <string>

#include "hasher.h"
#include "hasher_ripemd160.h"

hasher_ripemd160::hasher_ripemd160()
{
}

hasher_ripemd160::~hasher_ripemd160()
{
}

std::string hasher_ripemd160::get_name()
{
	return "ripemd160";
}

int hasher_ripemd160::get_hash_size() const
{
	return CryptoPP::RIPEMD160::DIGESTSIZE;
}

void hasher_ripemd160::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	CryptoPP::RIPEMD160().CalculateDigest(dest, in, in_size);
}
