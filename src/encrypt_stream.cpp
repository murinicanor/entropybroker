#include <string.h>
#include <string>

#include "error.h"
#include "encrypt_stream.h"
#include "encrypt_stream_3des.h"
#include "encrypt_stream_aes.h"
#include "encrypt_stream_blowfish.h"
#include "encrypt_stream_camellia.h"

encrypt_stream::encrypt_stream()
{
}

encrypt_stream::~encrypt_stream()
{
}

encrypt_stream * encrypt_stream::select_cipher(std::string type)
{
	if (type == "3des")
		return new encrypt_stream_3des();

	if (type == "aes")
		return new encrypt_stream_aes();

	if (type == "blowfish")
		return new encrypt_stream_blowfish();

	if (type == "camellia")
		return new encrypt_stream_camellia();

	error_exit("Cipher '%s' is not known", type.c_str());

	return NULL;
}
