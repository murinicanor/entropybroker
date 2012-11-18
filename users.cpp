// SVN: $Revision$
#include <stdlib.h>
#include <string>
#include <map>
#include <vector>
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
	user_map = new std::map<std::string, user_t>();

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

		std::vector<std::string> pars = split_string(line, "|");
		if (pars.size() == 1)
			error_exit("%s: seperator missing at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		user_t u;
		u.password = pars[1];
		if (pars.size() >= 3)
			u.max_get_bps = atoi(pars[2].c_str());
		else
			u.max_get_bps = -1;

		std::string username = pars[0];

		if (username.length() == 0 || u.password.length() == 0)
			error_exit("%s: username/password cannot be empty at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		(*user_map)[username] = u;
	}

	fh.close();
}

bool users::find_user(std::string username, user_t **u)
{
	my_mutex_lock(&lock);

	std::map<std::string, user_t>::iterator it = user_map -> find(username);
	if (it == user_map -> end())
	{
		my_mutex_unlock(&lock);
		return false;
	}

	*u = new user_t;

	(*u) -> password = it -> second.password;
	(*u) -> max_get_bps = it -> second.max_get_bps;

	(*u) -> last_get_message = 0.0;
	(*u) -> allowance = (*u) -> max_get_bps;

	my_mutex_unlock(&lock);

	return true;
}
