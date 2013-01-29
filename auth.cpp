// SVN: $Revision$
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
#include "scc.h"
#include "fips140.h"
#include "encrypt_stream.h"
#include "hasher.h"
#include "hasher_type.h"
#include "stirrer.h"
#include "stirrer_type.h"
#include "protocol.h"
#include "math.h"
#include "pool_crypto.h"
#include "pool.h"
#include "pools.h"
#include "statistics.h"
#include "statistics_global.h"
#include "statistics_user.h"
#include "users.h"

int auth_eb_user(int fd, int to, users *user_map, std::string & username_out, std::string & password, long long unsigned int *challenge, bool is_proxy_auth, bool *is_server_in, std::string & type, random_source *rs, encrypt_stream *es, hasher *mac, std::string handshake_hash, unsigned int max_get_put_size, statistics_global *sg)
{
	std::string host = get_endpoint_name(fd);

	const char *ts = is_proxy_auth ? "Proxy-auth" : "Connection";

	/* Inform the client about the hash-functions and ciphers that are used */
	std::string mac_data = mac -> get_name();
	std::string cipher_data = es -> get_name();

	if (send_length_data(fd, handshake_hash.c_str(), handshake_hash.size(), to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending handshake hash (fd: %d, host: %s)", ts, fd, host.c_str());
		return -1;
	}
	if (send_length_data(fd, mac_data.c_str(), mac_data.size(), to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending data MAC (fd: %d, host: %s)", ts, fd, host.c_str());
		return -1;
	}
	if (send_length_data(fd, cipher_data.c_str(), cipher_data.size(), to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending data cipher (fd: %d, host: %s)", ts, fd, host.c_str());
		return -1;
	}
	/////

	/* send random with which will be concatenated to the password and then hashed */
	long long unsigned int rnd = 9;
	rs -> get(reinterpret_cast<unsigned char *>(&rnd), sizeof rnd);

	char rnd_str[128];
	unsigned int rnd_str_size = snprintf(rnd_str, sizeof rnd_str, "%llu", rnd);

	*challenge = rnd;

	if (rnd_str_size == 0)
		error_exit("INTERNAL ERROR: random string is 0 characters!");

	if (send_length_data(fd, rnd_str, rnd_str_size, to) == -1)
	{
		dolog(LOG_INFO, "%s failure sending random (fd: %d, host: %s)", ts, fd, host.c_str());
		return -1;
	}
	/////

	/* receive username */
	char *username = NULL;
	unsigned int username_length = 0;
	if (recv_length_data(fd, &username, &username_length, to) == -1)
	{
		dolog(LOG_INFO, "%s receiving username (fd: %d, host: %s)", ts, fd, host.c_str());
		return -1;
	}

	dolog(LOG_INFO, "User '%s'[len: %d] requesting access (fd: %d, host: %s)", username, username_length, fd, host.c_str());

	if (username == NULL || username[0] == 0x00 || username_length == 0)
	{
		dolog(LOG_WARNING, "Empty username");
		sg -> put_history_log(HL_LOGIN_OTHER, host, "", "", get_ts(), 0, "empty username");
		free(username);
		return -1;
	}

	username_out.assign(username);

	bool user_known = user_map -> get_password(username_out, password);
	if (!user_known)
	{
		dolog(LOG_WARNING, "User '%s' not known, (fd: %d, host: %s)", username, host.c_str());

		sg -> put_history_log(HL_LOGIN_USER_FAIL, host, "", username_out, get_ts(), 0, "username not known");

		user_known = false;
	}
	free(username);
	/////

	/* receive hashed password */
	hasher *hh = hasher::select_hasher(handshake_hash);
	int hash_len = hh -> get_hash_size();

	char hash_cmp_str[256], *hash_cmp = reinterpret_cast<char *>(malloc(hash_len)), *hash_in = reinterpret_cast<char *>(malloc(hash_len));
	int hash_cmp_str_len = snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());

	if (!hash_cmp || !hash_in)
		error_exit("out of memory");

	hh -> do_hash((unsigned char *)hash_cmp_str, hash_cmp_str_len, reinterpret_cast<unsigned char *>(hash_cmp));

	if (READ_TO(fd, hash_in, hash_len, to) != hash_len)
	{
		dolog(LOG_INFO, "%s receiving hash failed (fd: %d, host: %s)", ts, fd, host.c_str());
		free(hash_cmp);
		free(hash_in);
		delete hh;
		return -1;
	}

	if (!user_known || memcmp(hash_cmp, hash_in, hash_len) != 0)
	{
		dolog(LOG_INFO, "%s authentication failed! (fd: %d, host: %s)", ts, fd, host.c_str());
		free(hash_cmp);
		free(hash_in);
		delete hh;
		sg -> put_history_log(HL_LOGIN_PW_FAIL, host, "", username_out, get_ts(), 0, "hash mismatch");
		return -1;
	}
	free(hash_cmp);
	free(hash_in);
	delete hh;
	/////

	/* receive a byte which indicates if the other end is a client or a server */
        char is_server = 0;
        if (READ_TO(fd, &is_server, 1, to) != 1)
        {
                dolog(LOG_INFO, "%s failed retrieving server/client (fd: %d, host: %s)", ts, fd, host.c_str());
                return -1;
        }
	*is_server_in = is_server ? true : false;
	/////

	/* receive a string which describes the other send */
	char *type_in = NULL;
	unsigned int type_in_size = 0;

	if (recv_length_data(fd, &type_in, &type_in_size, to) == -1)
	{
                dolog(LOG_INFO, "%s failed retrieving type (fd: %d, host: %s)", ts, fd, host.c_str());
		return -1;
	}
	type = std::string(type_in);
	free(type_in);
	/////

	/* how many bits can be put/get in one go */
	unsigned char max_get_put_size_bytes[4];
	uint_to_uchar(max_get_put_size, max_get_put_size_bytes);
	if (WRITE_TO(fd, max_get_put_size_bytes, 4, to) == -1)
	{
		dolog(LOG_INFO, "Connection closed (fd: %d, host: %s)", fd, host.c_str());
		return -1;
	}

	dolog(LOG_INFO, "%s authentication ok (fd: %d, host: %s)", ts, fd, host.c_str());

	double now_ts = get_ts();
	user_map -> set_last_login(username_out, now_ts);
	sg -> put_history_log(HL_LOGIN_OK, host, type, username_out, now_ts, 0, "");

	return 0;
}

int auth_eb(int fd, int to, users *user_map, std::string & username, std::string & password, long long unsigned int *challenge, bool *is_server_in, std::string & type, random_source *rs, encrypt_stream *enc, hasher *mac, std::string handshake_hash, unsigned int max_get_put_size, statistics_global *sg)
{
	char prot_ver[4 + 1] = { 0 };
	snprintf(prot_ver, sizeof prot_ver, "%04d", PROTOCOL_VERSION);

	if (WRITE_TO(fd, prot_ver, 4, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (0)", fd);
		return -1;
	}

	return auth_eb_user(fd, to, user_map, username, password, challenge, false, is_server_in, type, rs, enc, mac, handshake_hash, max_get_put_size, sg);
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

int auth_client_server_user(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type, std::string & cd, std::string & mh, unsigned int *max_get_put_size)
{
	char *hash_handshake = NULL;
	unsigned int hash_handshake_size = 0;
	if (recv_length_data(fd, &hash_handshake, &hash_handshake_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (t1)", fd);
		return -1;
	}
	char *mac_data = NULL;
	unsigned int mac_data_size = 0;
	if (recv_length_data(fd, &mac_data, &mac_data_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (t2)", fd);
		return -1;
	}
	mh.assign(mac_data);
	char *cipher_data = NULL;
	unsigned int cipher_data_size = 0;
	if (recv_length_data(fd, &cipher_data, &cipher_data_size, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (t3)", fd);
		return -1;
	}
	cd.assign(cipher_data);
	dolog(LOG_DEBUG, "handshake hash: %s, data mac: %s, data cipher: %s", hash_handshake, mac_data, cipher_data);

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

	hasher *hh = hasher::select_hasher(hash_handshake);
	int hash_len = hh -> get_hash_size();

	char hash_cmp_str[256], *hash_cmp = reinterpret_cast<char *>(malloc(hash_len)), *hash_in = reinterpret_cast<char *>(malloc(hash_len));
	int hash_cmp_str_len = snprintf(hash_cmp_str, sizeof hash_cmp_str, "%s %s", rnd_str, password.c_str());
	free(rnd_str);

	if (!hash_cmp || !hash_in)
		error_exit("out of memory");

	hh -> do_hash((unsigned char *)hash_cmp_str, hash_cmp_str_len, reinterpret_cast<unsigned char *>(hash_cmp));

	if (WRITE_TO(fd, hash_cmp, hash_len, to) == -1)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (a3)", fd);

		free(hash_cmp);
		free(hash_in);
		delete hh;

		return -1;
	}

	free(hash_cmp);
	free(hash_in);
	delete hh;

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
		return -1;
	}

	unsigned char max_get_put_size_bytes[4];
	if (READ_TO(fd, max_get_put_size_bytes, 4, to) != 4)
	{
		dolog(LOG_INFO, "Connection for fd %d closed (m3)", fd);
		return -1;
	}
	*max_get_put_size = uchar_to_uint(max_get_put_size_bytes);

	return 0;
}

int auth_client_server(int fd, int to, std::string & username, std::string & password, long long unsigned int *challenge, bool is_server, std::string type, std::string & cd, std::string &mh, unsigned int *max_get_put_size)
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

	return auth_client_server_user(fd, to, username, password, challenge, is_server, type, cd, mh, max_get_put_size);
}
