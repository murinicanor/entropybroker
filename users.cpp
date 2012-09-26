// SVN: $Id$
#include <string>
#include <map>
#include <fstream>
#include <pthread.h>

#include "error.h"
#include "log.h"
#include "utils.h"
#include "users.h"

users::users(std::string filename_in) : filename(filename_in)
{
	pthread_check(pthread_mutex_init(&lock, &global_mutex_attr), "pthread_mutex_init");

	user_map = NULL;
	load_usermap();
}

users::~users()
{
	delete user_map;

	pthread_check(pthread_mutex_destroy(&lock), "pthread_mutex_destroy");
}

void users::reload()
{
	my_mutex_lock(&lock);

	delete user_map;

	load_usermap();

	my_mutex_unlock(&lock);
}

void users::load_usermap()
{
	user_map = new std::map<std::string, std::string>();

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

		(*user_map)[username] = password;
	}

	fh.close();
}

bool users::find_user(std::string username, std::string & password)
{
	my_mutex_lock(&lock);

	password.assign("INVALID PASSWORd");

	std::map<std::string, std::string>::iterator it = user_map -> find(username);
	if (it == user_map -> end())
	{
		my_mutex_unlock(&lock);
		return false;
	}

	password.assign(it -> second);

	my_mutex_unlock(&lock);

	return true;
}
