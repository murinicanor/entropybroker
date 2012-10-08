// SVN: $Revision$
#include <string>

#include "hasher.h"
#include "hasher_whirlpool.h"

hasher_whirlpool::hasher_whirlpool()
{
}

hasher_whirlpool::~hasher_whirlpool()
{
}

std::string hasher_whirlpool::get_name()
{
	return "whirlpool";
}

int hasher_whirlpool::get_hash_size() const
{
	return CryptoPP::Whirlpool::DIGESTSIZE;
}

void hasher_whirlpool::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	CryptoPP::Whirlpool().CalculateDigest(dest, in, in_size);
}
