#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>
#include <fstream>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "users.h"

int auth_eb_user(int fd, int to, users *user_map, std::string & password, long long unsigned int *challenge, bool is_proxy_auth)
{
	const char *ts = is_proxy_auth ? "Proxy-auth" : "Connection";

	long long unsigned int rnd = 9;

	if (RAND_bytes((unsigned char *)&rnd, sizeof rnd) == 0)
		error_exit("RAND_bytes fails");

	char rnd_str[128];
	unsigned char rnd_str_size = snprintf(rnd_str, sizeof rnd_str, "%llu", rnd);

	*challenge = rnd;

	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");

	if (WRITE_TO(fd, (char *)&rnd_str_size, 1, to) == -1)
	{
		dolog(LOG_INFO, "%s for fd %d closed (1)", ts, fd);
		return -1;
	}
	if (WRITE_TO(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "%s for fd %d closed (2)", ts, fd);
		return -1;
	}

	unsigned char username_length = 0;
	if (READ_TO(fd, (char *)&username_length, 1, to) != 1)
	{
		dolog(LOG_INFO, "%s for fd %d closed (u1)", ts, fd);
		return -1;
	}
	char username[255 + 1] = { 0 };
	if (username_length > 0)
	{
		if (READ_TO(fd, username, username_length, to) != username_length)
		{
			dolog(LOG_INFO, "%s for fd %d closed (u2)", ts, fd);
			return -1;
		}

		username[username_length] = 0x00;
	}
	dolog(LOG_INFO, "User '%s' requesting access", username);

	if (username[0] == 0x00)
	{
		dolog(LOG_WARNING, "Empty username");
		return -1;
	}

	bool user_known = user_map -> find(usesrname, password);
	if (!user_known)
	{
		dolog(LOG_WARNING, "User '%s' not known", username);

		user_known = false;
	}

	char hash_cmp_str[256], hash_cmp[SHA512_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());

	SHA512((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), (unsigned char *)hash_cmp);

	char hash_in[SHA512_DIGEST_LENGTH];
	if (READ_TO(fd, hash_in, SHA512_DIGEST_LENGTH, to) != SHA512_DIGEST_LENGTH)
	{
		dolog(LOG_INFO, "%s for fd %d closed (3)", ts, fd);
		return -1;
	}

	if (user_known && memcmp(hash_cmp, hash_in, SHA512_DIGEST_LENGTH) == 0)
	{
		dolog(LOG_INFO, "%s for fd %d: authentication ok", ts, fd);
		return 0;
	}

	dolog(LOG_INFO, "%s for fd %d: authentication failed!", ts, fd);

	return -1;
}

int auth_eb(int fd, int to, users *user_map, std::string & password, long long unsigned int *challenge)
{
	char prot_ver[4 + 1];
	snprintf(prot_ver, 4, "%d", PROTOCOL_VERSION);

	if (WRITE_TO(fd, prot_ver, 4, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}

	return auth_eb_user(fd, to, user_map, password, challenge, false);
}

bool get_auth_from_file(char *filename, std::string & username, std::string & password)
{
	struct stat ss;

	if (stat(filename, &ss) == -1)
		error_exit("stat(%s) failed", filename);

	if (ss.st_mode & (S_IRWXG | S_IRWXO))
		error_exit("file %s must only readable by its owner", filename);

	std::ifstream fh(filename);
	if (!fh.is_open())
		error_exit("Cannot open %s", filename);

	std::string line;
	std::getline(fh, line);
	username.assign(line);

	std::getline(fh, line);
	password.assign(line);

	fh.close();

	return true;
}

int auth_client_server_user(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge)
{
	char rnd_str[128];
	unsigned char rnd_str_size;
	if (READ_TO(fd, (char *)&rnd_str_size, 1, to) != 1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (1)", fd);
		return -1;
	}
	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");
	if (rnd_str_size >= sizeof rnd_str)
		error_exit("INTERNAL ERROR: random string too long!");
	if (READ_TO(fd, rnd_str, rnd_str_size, to) != rnd_str_size)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (2)", fd);
		return -1;
	}
	rnd_str[rnd_str_size] = 0x00;

	char *dummy = NULL;
	*challenge = strtoull(rnd_str, &dummy, 10);

	unsigned char username_length = username.length();
	if (WRITE_TO(fd, (char *)&username_length, 1, to) != 1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (u1)", fd);
		return -1;
	}
	if (WRITE_TO(fd, (char *)username.c_str(), username_length, to) != username_length)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (u1)", fd);
		return -1;
	}

	char hash_cmp_str[256], hash_cmp[SHA512_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());

	SHA512((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), (unsigned char *)hash_cmp);

	if (WRITE(fd, hash_cmp, SHA512_DIGEST_LENGTH) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)", fd);
		return -1;
	}

	return 0;
}

int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge)
{
	char prot_ver[4 + 1];

	if (READ_TO(fd, prot_ver, 4, to) != 4)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}
	prot_ver[4] = 0x00;
	int eb_ver = atoi(prot_ver);
	if (eb_ver != PROTOCOL_VERSION)
		error_exit("Broker server has unsupported protocol version %d! (expecting %d)", eb_ver, PROTOCOL_VERSION);

	return auth_client_server_user(fd, to, username, password, challenge);
}
