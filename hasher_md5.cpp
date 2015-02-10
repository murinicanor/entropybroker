#include <string>

#include "hasher.h"
#include "hasher_md5.h"

hasher_md5::hasher_md5()
{
}

hasher_md5::~hasher_md5()
{
}

std::string hasher_md5::get_name()
{
	return "md5";
}

int hasher_md5::get_hash_size() const
{
	return CryptoPP::Weak::MD5::DIGESTSIZE;
}

void hasher_md5::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	// FIXME thread safe?
	CryptoPP::Weak::MD5().CalculateDigest(dest, in, in_size);
}
