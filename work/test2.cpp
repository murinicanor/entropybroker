#include <stdio.h>
#include <string>
#include <string.h>

#include "encrypt_stream.h"

int main(int argc, char *argv[])
{
	encrypt_stream *p1 = encrypt_stream::select_cipher(argv[1]);
	encrypt_stream *p2 = encrypt_stream::select_cipher(argv[1]);

	printf("name: %s\n", p1 -> get_name().c_str());
	printf("ivec size: %d\n", p1 -> get_ivec_size());
	printf("key size: %d\n", p1 -> get_key_size());
	unsigned char ivec[8] = { 0 };
	unsigned char key[24] = { 0 };
	sprintf((char *)key, "password");
	p1 -> init(key, sizeof key, ivec);
	p2 -> init(key, sizeof key, ivec);

	char *in = "Dit is een test!!!";
	int len = strlen(in) + 1;
	printf("len: %d\n", len);
	char temp[4096] = { 0 };
	char out[4096] = { 0 };

	p1 -> encrypt((unsigned char *)in, len, (unsigned char *)temp);
	p2 -> decrypt((unsigned char *)temp, len, (unsigned char *)out);

	delete p2;
	delete p1;

	printf("%s\n", out);

	return 0;
}
