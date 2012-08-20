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

int auth_eb(int fd, int to, std::map<std::string, std::string> *users, std::string & password, long long unsigned int *challenge)
{
	long long unsigned int rnd = 9;
	RAND_bytes((unsigned char *)&rnd, sizeof rnd);

	char rnd_str[128];
	unsigned char rnd_str_size = snprintf(rnd_str, sizeof rnd_str, "%llu", rnd);

	*challenge = rnd;

	char prot_ver[4+1];
	snprintf(prot_ver, 4, "%d", PROTOCOL_VERSION);
	if (WRITE_TO(fd, prot_ver, 4, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}

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

	// not used yet
	unsigned char username_length = 0;
	if (READ_TO(fd, (char *)&username_length, 1, to) != 1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (u1)", fd);
		return -1;
	}
	char username[255 + 1] = { 0 };
	if (username_length > 0)
	{
		if (READ_TO(fd, username, username_length, to) != username_length)
		{
			dolog(LOG_INFO, "Connection for fd %d closed (u2)", fd);
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

	std::map<std::string, std::string>::iterator it = users -> find(username);
	if (it == users -> end())
	{
		dolog(LOG_WARNING, "User '%s' not known", username);
		return -1;
	}

	password.assign(it -> second);

	char hash_cmp_str[256], hash_cmp[SHA_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());

        SHA1((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), (unsigned char *)hash_cmp);

	char hash_in[SHA_DIGEST_LENGTH];
	if (READ_TO(fd, hash_in, SHA_DIGEST_LENGTH, to) <= 0)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)", fd);
		return -1;
	}

	if (memcmp(hash_cmp, hash_in, SHA_DIGEST_LENGTH) == 0)
	{
		dolog(LOG_INFO, "Connection for fd %d: authentication ok", fd);
		return 0;
	}

	dolog(LOG_INFO, "Connection for fd %d: authentication failed!", fd);

	return -1;
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

int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge)
{
	char rnd_str[128];
	unsigned char rnd_str_size;
	char prot_ver[4 + 1];

	if (READ_TO(fd, prot_ver, 4, to) <= 0)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}
	prot_ver[4] = 0x00;
	int eb_ver = atoi(prot_ver);
	if (eb_ver != PROTOCOL_VERSION)
		error_exit("Broker server has unsupported protocol version %d! (expecting %d)", eb_ver, PROTOCOL_VERSION);

	if (READ_TO(fd, (char *)&rnd_str_size, 1, to) <= 0)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (1)", fd);
		return -1;
	}
	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");
	if (rnd_str_size >= sizeof rnd_str)
		error_exit("INTERNAL ERROR: random string too long!");
	if (READ_TO(fd, rnd_str, rnd_str_size, to) <= 0)
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

	char hash_cmp_str[256], hash_cmp[SHA_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());

        SHA1((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), (unsigned char *)hash_cmp);

	if (WRITE(fd, hash_cmp, SHA_DIGEST_LENGTH) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (3)", fd);
		return -1;
	}

	return 0;
}

std::map<std::string, std::string> * load_usermap(std::string filename)
{
	std::map<std::string, std::string> *output = new std::map<std::string, std::string>();

        std::ifstream fh(filename.c_str());
        if (!fh.is_open())
                error_exit("Cannot open %s", filename.c_str());

	std::string line;
	int line_nr = 0;
	while(!fh.eof())
	{
		std::getline(fh, line);
		if (line.length() == 0)
			break;

		line_nr++;

                size_t pos = line.find("|");
                if (pos == std::string::npos)
                        error_exit("%s: seperator missing at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		std::string username = line.substr(0, pos);
		std::string password = line.substr(pos + 1);

		if (username.length() == 0 || password.length() == 0)
			error_exit("%s: username/password cannot be empty at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		(*output)[username] = password;
	}

	fh.close();

	return output;
}
