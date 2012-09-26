// SVN: $Revision$
#include <openssl/md5.h>

#include "hasher.h"
#include "hasher_md5.h"

hasher_md5::hasher_md5()
{
}

hasher_md5::~hasher_md5()
{
}

int hasher_md5::get_hash_size() const
{
	return MD5_DIGEST_LENGTH;
}

void hasher_md5::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	MD5(in, in_size, dest);
}
