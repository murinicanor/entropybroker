// SVN: $Revision$
#include <string>
#include "hasher.h"
#include "hasher_md5.h"
#include "hasher_ripemd160.h"
#include "hasher_sha512.h"
#include "hasher_whirlpool.h"

hasher::hasher()
{
}

hasher::~hasher()
{
}

hasher *hasher::select_hasher(std::string type)
{
	if (type == "md5")
		return new hasher_md5();

	if (type == "ripemd160")
		return new hasher_ripemd160();

	if (type == "sha512")
		return new hasher_sha512();

	if (type == "whirlpool")
		return new hasher_whirlpool();

	return NULL;
}
