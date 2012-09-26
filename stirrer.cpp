// SVN: $Revision$
#include <string>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/blowfish.h>

#include "error.h"
#include "random_source.h"
#include "utils.h"
#include "stirrer.h"

stirrer::stirrer(random_source_t rs_in) : rs(rs_in)
{
}

stirrer::~stirrer()
{
}
