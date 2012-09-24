// SVN: $Id$
#include <openssl/whrlpool.h>

#include "hasher.h"
#include "hasher_whirlpool.h"

hasher_whirlpool::hasher_whirlpool()
{
}

hasher_whirlpool::~hasher_whirlpool()
{
}

int hasher_whirlpool::get_hash_size() const
{
	return WHIRLPOOL_DIGEST_LENGTH;
}

void hasher_whirlpool::do_hash(unsigned char *in, int in_size, unsigned char *dest)
{
	WHIRLPOOL(in, in_size, dest);
}
