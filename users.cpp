#include <string>
#include <map>

#include "error.h"
#include "log.h"
#include "users.h"

users::users(std::string filename_in) : filename(filename_in)
{
	user_map = NULL;
	load_usermap();
}

users::~users()
{
	delete user_map;
}

void users::load_usermap()
{
	delete user_map;
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

		(*output)[username] = password;
	}

	fh.close();

	return output;
}

bool users::find_user(std::string username, std::string & password)
{
	password.assign("INVALID PASSWORd");

	std::map<std::string, std::string>::iterator it = user_map -> find(username);
	if (it == user_map -> end())
		return false;

	password.assign(it -> second);

	return true;
}
