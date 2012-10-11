#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>

unsigned char key[32] = { 1, 2, 3, 4 /* etc */ };
unsigned char ivec[16] = "bla";

unsigned char buffer1[4096] = { 0 };
unsigned char buffer2[4096] = { 0 };

void * thread1(void *data)
{
	for(;;)
	{
		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption *enc = new CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption(key, sizeof key, ivec);

		enc -> ProcessData(buffer2, buffer1, sizeof buffer2);

		delete enc;

		memcpy(key, buffer2, 32); // produce variations
		memcpy(ivec, &buffer2[32], 16);
	}
}

void * thread2(void *data)
{
	for(;;)
	{
		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption *dec = new CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption(key, sizeof key, ivec);

		dec -> ProcessData(buffer2, buffer1, sizeof buffer2);

		delete dec;

		memcpy(key, buffer2, 32); // produce variations
		memcpy(ivec, &buffer2[32], 16);
	}
}

int main(int argc, char *argv[])
{
	pthread_t th1;
	pthread_create(&th1, NULL, thread1, NULL);
	pthread_t th2;
	pthread_create(&th2, NULL, thread2, NULL);
	pthread_t th3;
	pthread_create(&th3, NULL, thread1, NULL);

	for(;;)
		sleep(60);

	return 0;
}
