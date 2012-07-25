#include <openssl/sha.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "utils.h"
#include "log.h"

int auth_eb(int fd, char *password, int to)
{
	long int rnd = lrand48();
	char rnd_str[128];
	unsigned char rnd_str_size = snprintf(rnd_str, sizeof rnd_str, "%d", rnd);

	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");

	if (WRITE_TO(fd, &rnd_str_size, 1, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (1)");
		return -1;
	}
	if (WRITE_TO(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (2)");
		return -1;
	}

	char hash_cmp_str[256], hash_cmp[SHA_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password);

        SHA1(hash_cmp_str, strlen(hash_cmp_str), hash_cmp);

	char hash_in[SHA_DIGEST_LENGTH];
	if (READ(fd, hash_in, SHA_DIGEST_LENGTH, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)");
		return -1;
	}

	if (memcmp(hash_cmp, hash_in, SHA_DIGEST_LENGTH) == 0)
	{
		dolog(LOG_INFO, "Connection for fd %d: authentication failed");
		return 0;
	}

	return -1;
}

char * get_password_from_file(char *filename)
{
	struct stat ss;

	if (stat(filename, &ss) == -1)
		error_exit("stat(%s) failed", filename);

	if (ss.st_mode != 00400 && ss.st_mode != 00600)
		error_exit("file %s must only readable by its owner", filename);

	FILE *fh = fopen(filename, "rb");
	if (!fh)
		error_exit("failed to open %s", filename);

	char password[128];

	if (fgets(password, sizeof password, fh) == NULL)
		error_exit("Failed to read from %s", filename);

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

	if (READ_TO(fd, &rnd_str_size, 1, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (1)");
		return -1;
	}
	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");
	if (rnd_str_size > sizeof rnd_str)
		error_exit("INTERNAL ERROR: random string too long!");
	if (READ_TO(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (2)");
		return -1;
	}

	char hash_cmp_str[256], hash_cmp[SHA_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password);

        SHA1(hash_cmp_str, strlen(hash_cmp_str), hash_cmp);

	char hash_in[SHA_DIGEST_LENGTH];
	if (WRITE(fd, hash_in, SHA_DIGEST_LENGTH, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)");
		return -1;
	}

	return 0;
}
