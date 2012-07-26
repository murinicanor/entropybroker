#include <openssl/sha.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "error.h"
#include "utils.h"
#include "log.h"

int auth_eb(int fd, char *password, int to)
{
	long int rnd = myrand();
	char rnd_str[128];
	unsigned char rnd_str_size = snprintf(rnd_str, sizeof rnd_str, "%ld", rnd);

	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");

	if (WRITE_TO(fd, (char *)&rnd_str_size, 1, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (1)", fd);
		return -1;
	}
	if (WRITE_TO(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (2)", fd);
		return -1;
	}

	char hash_cmp_str[256], hash_cmp[SHA_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password);

        SHA1((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), (unsigned char *)hash_cmp);

	char hash_in[SHA_DIGEST_LENGTH];
	if (READ_TO(fd, hash_in, SHA_DIGEST_LENGTH, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)", fd);
		return -1;
	}
printf("%d %s\n", SHA_DIGEST_LENGTH, hash_cmp_str);

	if (memcmp(hash_cmp, hash_in, SHA_DIGEST_LENGTH) == 0)
	{
		dolog(LOG_INFO, "Connection for fd %d: authentication ok", fd);
		return 0;
	}

	dolog(LOG_INFO, "Connection for fd %d: authentication failed!", fd);

	return -1;
}

char * get_password_from_file(char *filename)
{
	struct stat ss;

	if (stat(filename, &ss) == -1)
		error_exit("stat(%s) failed", filename);

	if (ss.st_mode & (S_IRWXG | S_IRWXO))
		error_exit("file %s must only readable by its owner", filename);

	FILE *fh = fopen(filename, "rb");
	if (!fh)
		error_exit("failed to open %s", filename);

	char password[128];

	if (fgets(password, sizeof password, fh) == NULL)
		error_exit("Failed to read from %s", filename);
	char *lf = strchr(password, '\n');
	if (lf)
		*lf = 0x00;

	fclose(fh);

	char *result = strdup(password);
	if (!result)
		error_exit("strdup failed");

	return result;
}

int auth_client_server(int fd, char *password, int to)
{
	char rnd_str[128];
	unsigned char rnd_str_size;

	if (READ_TO(fd, (char *)&rnd_str_size, 1, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (1)", fd);
		return -1;
	}
	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");
	if (rnd_str_size >= sizeof rnd_str)
		error_exit("INTERNAL ERROR: random string too long!");
	if (READ_TO(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (2)", fd);
		return -1;
	}
	rnd_str[rnd_str_size] = 0x00;

	char hash_cmp_str[256], hash_cmp[SHA_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password);
printf("%d %s\n", SHA_DIGEST_LENGTH, hash_cmp_str);

        SHA1((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), (unsigned char *)hash_cmp);

	if (WRITE(fd, hash_cmp, SHA_DIGEST_LENGTH) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)", fd);
		return -1;
	}

	return 0;
}
