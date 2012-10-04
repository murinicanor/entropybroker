// SVN: $Revision$
#include <openssl/blowfish.h>
#include <openssl/sha.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string>
#include <map>
#include <vector>
#include <fstream>

#include "error.h"
#include "random_source.h"
#include "utils.h"
#include "log.h"
#include "encrypt_stream.h"
#include "protocol.h"
#include "users.h"

int auth_eb_user(int fd, int to, users *user_map, std::string & password, long long unsigned int *challenge, bool is_proxy_auth, bool *is_server_in, std::string & type, random_source_t rs, encrypt_stream *es)
{
	const char *ts = is_proxy_auth ? "Proxy-auth" : "Connection";

	/* Inform the client about the hash-functions and ciphers that are used */
	std::string hash_handshake = "sha512";
	std::string mac_data = "sha256";
	std::string cipher_data = es -> get_name();

	if (send_length_data(fd, hash_handshake.c_str(), hash_handshake.size(), to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending handshake hash (fd: %d)", ts, fd);
		return -1;
	}
	if (send_length_data(fd, mac_data.c_str(), mac_data.size(), to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending data MAC (fd: %d)", ts, fd);
		return -1;
	}
	if (send_length_data(fd, cipher_data.c_str(), cipher_data.size(), to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending data cipher (fd: %d)", ts, fd);
		return -1;
	}
	/////

	/* send random with which will be concatenated to the password and then hashed */
	long long unsigned int rnd = 9;
	get_random(rs, reinterpret_cast<unsigned char *>(&rnd), sizeof rnd);

	char rnd_str[128];
	unsigned int rnd_str_size = snprintf(rnd_str, sizeof rnd_str, "%llu", rnd);

	*challenge = rnd;

	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");

	if (send_length_data(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending random (fd: %d)", ts, fd);
		return -1;
	}
	/////

	/* receive username */
	char *username = NULL;
	unsigned int username_length = 0;
	if (recv_length_data(fd, &username, &username_length, to) == -1)
	{
		dolog(LOG_INFO, "%s receiving username (fd: %d)", ts, fd);
		return -1;
	}

	dolog(LOG_INFO, "User '%s'[len: %d] requesting access", username, username_length);

	if (username == NULL || username[0] == 0x00 || username_length == 0)
	{
		dolog(LOG_WARNING, "Empty username");
		free(username);
		return -1;
	}

	bool user_known = user_map -> find_user(username, password);
	if (!user_known)
	{
		dolog(LOG_WARNING, "User '%s' not known", username);

		user_known = false;
	}
	free(username);
	/////

	/* receive hashed password */
	char hash_cmp_str[256], hash_cmp[SHA512_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());

	SHA512((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), reinterpret_cast<unsigned char *>(hash_cmp));

	char hash_in[SHA512_DIGEST_LENGTH];
	if (READ_TO(fd, hash_in, SHA512_DIGEST_LENGTH, to) != SHA512_DIGEST_LENGTH)
	{
		dolog(LOG_INFO, "%s receiving hash failed (fd: %d)", ts, fd);
		return -1;
	}

	if (!user_known || memcmp(hash_cmp, hash_in, SHA512_DIGEST_LENGTH) != 0)
	{
		dolog(LOG_INFO, "%s authentication failed! (fd: %d)", ts, fd);
		return -1;
	}
	/////

	/* receive a byte which indicates if the other end is a client or a server */
        char is_server = 0;
        if (READ_TO(fd, &is_server, 1, to) != 1)
        {
                dolog(LOG_INFO, "%s failed retrieving server/client (fd: %d)", ts, fd);
                return -1;
        }
	*is_server_in = is_server ? true : false;
	/////

	/* receive a string which describes the other send */
	char *type_in = NULL;
	unsigned int type_in_size = 0;

	if (recv_length_data(fd, &type_in, &type_in_size, to) == -1)
	{
                dolog(LOG_INFO, "%s failed retrieving type (fd: %d)", ts, fd);
		return -1;
	}
	type = std::string(type_in);
	free(type_in);
	/////

	dolog(LOG_INFO, "%s authentication ok (fd: %d)", ts, fd);

	return 0;
}

int auth_eb(int fd, int to, users *user_map, std::string & password, long long unsigned int *challenge, bool *is_server_in, std::string & type, random_source_t rs, encrypt_stream *es)
{
	char prot_ver[4 + 1] = { 0 };
	snprintf(prot_ver, sizeof prot_ver, "%04d", PROTOCOL_VERSION);

	if (WRITE_TO(fd, prot_ver, 4, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}

	return auth_eb_user(fd, to, user_map, password, challenge, false, is_server_in, type, rs, es);
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

int auth_client_server_user(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type)
{
	char *hash_handshake = NULL;
	unsigned int hash_handshake_size = 0;
	if (recv_length_data(fd, &hash_handshake, &hash_handshake_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (t1)", fd);
		return -1;
	}
	if (strcmp(hash_handshake, "sha512") != 0)
		error_exit("Server uses unsupported (%s) hash function for password hash (sha512 expected)");
	char *mac_data = NULL;
	unsigned int mac_data_size = 0;
	if (recv_length_data(fd, &mac_data, &mac_data_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (t2)", fd);
		return -1;
	}
	if (strcmp(mac_data, "sha256") != 0)
		error_exit("Server uses unsupported (%s) hash function for data mac (sha256 expected)");
	char *cipher_data = NULL;
	unsigned int cipher_data_size = 0;
	if (recv_length_data(fd, &cipher_data, &cipher_data_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (t3)", fd);
		return -1;
	}
	if (strcmp(cipher_data, "blowfish") != 0)
		error_exit("Server uses unsupported (%s) cipher function for data encryption (blowfish expected)");
	printf("%s / %s / %s\n", hash_handshake, mac_data, cipher_data);

	char *rnd_str = NULL;
	unsigned int rnd_str_size = 0;
	if (recv_length_data(fd, &rnd_str, &rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (a1)", fd);
		return -1;
	}

	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");

	char *dummy = NULL;
	*challenge = strtoull(rnd_str, &dummy, 10);

	unsigned int username_length = username.length();
	if (send_length_data(fd, const_cast<char *>(username.c_str()), username_length, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (a2)", fd);
		free(rnd_str);
		return -1;
	}

	char hash_cmp_str[256], hash_cmp[SHA512_DIGEST_LENGTH];
	snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());
	free(rnd_str);

	SHA512((const unsigned char *)hash_cmp_str, strlen(hash_cmp_str), reinterpret_cast<unsigned char *>(hash_cmp));

	if (WRITE_TO(fd, hash_cmp, SHA512_DIGEST_LENGTH, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (a3)", fd);
		return -1;
	}

	char is_server_byte = is_server ? 1 : 0;
	if (WRITE_TO(fd, &is_server_byte, 1, to) != 1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (m1)", fd);
		return -1;
	}

	unsigned int type_length = type.length();
	if (send_length_data(fd, const_cast<char *>(type.c_str()), type_length, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (m2)", fd);
		free(rnd_str);
		return -1;
	}

	return 0;
}

int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type)
{
	char prot_ver[4 + 1] = { 0 };

	if (READ_TO(fd, prot_ver, 4, to) != 4)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}
	int eb_ver = atoi(prot_ver);
	if (eb_ver != PROTOCOL_VERSION)
		error_exit("Broker server has unsupported protocol version %d! (expecting %d)", eb_ver, PROTOCOL_VERSION);

	return auth_client_server_user(fd, to, username, password, challenge, is_server, type);
}
