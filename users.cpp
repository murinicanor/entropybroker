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

users::users(std::string filename_in, int default_max_get_bps_in) : filename(filename_in), default_max_get_bps(default_max_get_bps_in)
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
	my_mutex_lock(&lock); // FIXME writelock

	std::map<std::string, user_t>::iterator it;
	for(it = user_map -> begin(); it != user_map -> end(); it++)
		pthread_check(pthread_mutex_destroy(&it -> second.lck), "pthread_mutex_destroy");

	delete user_map;

	load_usermap();

	my_mutex_unlock(&lock); // FIXME writelock
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
			u.allowance = u.max_get_bps = atoi(pars[2].c_str());
		else
			u.allowance = u.max_get_bps = default_max_get_bps;
		u.last_get_message = 0.0;

		pthread_check(pthread_mutex_init(&u.lck, &global_mutex_attr), "pthread_mutex_init");

		std::string username = pars[0];

		if (username.length() == 0 || u.password.length() == 0)
			error_exit("%s: username/password cannot be empty at line %d (%s)", filename.c_str(), line_nr, line.c_str());

		(*user_map)[username] = u;
	}

	fh.close();
}

user_t *users::find_user(std::string username)
{
	std::map<std::string, user_t>::iterator it = user_map -> find(username);
	if (it == user_map -> end())
		return NULL;

	return &it -> second;
}

bool users::get_password(std::string username, std::string & password)
{
	password.assign("DEFINATELY WRONG PASSWORd");

	my_mutex_lock(&lock); // FIXME readlock

	user_t *u = find_user(username);
	if (u)
		password.assign(u -> password);

	my_mutex_unlock(&lock); // FIXME readlock

	return u ? true : false;
}

int users::calc_max_allowance(std::string username, double now, int n_requested)
{
	my_mutex_lock(&lock); // FIXME readlock

	int n = -1;

	user_t *u = find_user(username);

	if (u)
	{
		my_mutex_lock(&u -> lck);

		double rate = u -> max_get_bps;	// unit: messages
		double per = 1.0;	// unit: seconds
		double allowance = u -> allowance; // unit: messages

		double last_check = u -> last_get_message; // floating-point, e.g. usec accuracy. Unit: seconds

		double time_passed = now - last_check;
		allowance += time_passed * (rate / per);

		if (allowance > rate)
			allowance = rate; // throttle

		if (allowance < 8.0) // 8 bits in a byte
			n = 0;
		else
			n = mymin(n_requested, allowance);
	}

	return n;
}

bool  users::use_allowance(std::string username, int n)
{
	user_t *u = find_user(username);

	if (u)
	{
		u -> allowance -= n;

		u -> last_get_message = get_ts();

		my_mutex_unlock(&u -> lck);
	}

	my_mutex_unlock(&lock); // FIXME readlock

	return u ? true : false;
}

bool users::cancel_allowance(std::string username)
{
	user_t *u = find_user(username);

	if (u)
		my_mutex_unlock(&u -> lck);

	my_mutex_unlock(&lock); // FIXME readlock

	return u ? true : false;
}
