#include <string>
#include <string.h>
#include <stdio.h>
#include <openssl/des.h>

int ivec_offset = 0, ivec_offset2 = 0;
DES_cblock iv, iv2;
DES_key_schedule ks1, ks2, ks3;

int main(int argc, char *argv[])
{
	char *key_in = "dit is een test password";
	int key_len = strlen(key_in);
	unsigned char ivec_in[8] = { 0, 1, 2, 3, 4, 5, 6, 7 };

	DES_cblock dk;

	char temp_key[24] = { 0 };
	memcpy(temp_key, key_in, key_len);

	memcpy(dk, &temp_key[0], 8);
	DES_set_odd_parity(&dk);
	if (DES_is_weak_key(&dk) == 1)
		return false;
	DES_set_key_unchecked(&dk, &ks1);

	memcpy(dk, &temp_key[8], 8);
	DES_set_odd_parity(&dk);
	if (DES_is_weak_key(&dk) == 1)
		return false;
	DES_set_key_unchecked(&dk, &ks2);

	memcpy(dk, &temp_key[16], 8);
	DES_set_odd_parity(&dk);
	if (DES_is_weak_key(&dk) == 1)
		return false;
	DES_set_key_unchecked(&dk, &ks3);

	memcpy(iv, ivec_in, 8);
	memcpy(iv2, ivec_in, 8);

	char in[] = "test";
	char temp[4096] = { 0 };
	char out[4096] = { 0 };
	int len = strlen(in) + 1;

	DES_ede3_cfb64_encrypt((const unsigned char *)in, (unsigned char *)temp, len, &ks1, &ks2, &ks3, &iv, &ivec_offset, DES_ENCRYPT);

	printf("%d\n", ivec_offset);

	DES_ede3_cfb64_encrypt((const unsigned char *)temp, (unsigned char *)out, len, &ks1, &ks2, &ks3, &iv2, &ivec_offset2, DES_DECRYPT);

	printf("%s\n", out);

	return 0;
}
