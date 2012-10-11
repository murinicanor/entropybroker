// SVN: $Revision$
#include <string>

#include "stirrer.h"
#include "hasher.h"
#include "random_source.h"
#include "pool_crypto.h"

pool_crypto::pool_crypto(stirrer *s_in, hasher *h_in, random_source_t *rs_in) : s(s_in), h(h_in), rs(*rs_in)
{
}
