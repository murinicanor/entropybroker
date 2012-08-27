#include <string>
#include <map>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/blowfish.h>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "math.h"
#include "protocol.h"
#include "users.h"
#include "auth.h"
#include "kernel_prng_io.h"

#define DEFAULT_COMM_TO 15
const char *pid_file = PID_DIR "/proxy_knuth.pid";
const char *client_type = "proxy_knuth";

typedef struct
{
	int fd;
	std::string password;
	long long unsigned int challenge;
} proxy_client_t;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void help()
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-j adapter  adapter to listen on\n");
	printf("-p port   port to listen on\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
	printf("-U file   read u/p for clients from file\n");
}

int main(int argc, char *argv[])
{
	char *host = NULL, *listen_adapter = NULL;
	int port = 55225, listen_port = 55225;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	std::string username, password;
	std::string clients_auths;

	printf("proxy_knuth, (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "U:hf:X:P:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'U':
				clients_auths = optarg;
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'i':
				host = optarg;
				break;

			case 's':
				log_syslog = true;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = true;
				log_console = true;
				break;

			case 'h':
				help();
				return 0;

			default:
				help();
				return 1;
		}
	}

	if (username.length() == 0 || password.length() == 0)
		error_exit("password + username cannot be empty");

	if (clients_auths.length() == 0)
		error_exit("No file with usernames + passwords selected for client authentication");

	if (!host)
		error_exit("No host to connect to selected");

	(void)umask(0177);
	set_logging_parameters(log_console, log_logfile, log_syslog);

	users *user_map = new users(clients_auths);

	protocol *p = new protocol(host, port, username, password, false, client_type);

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	no_core();

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	proxy_client_t *clients[2] = { new proxy_client_t, new proxy_client_t };
	int listen_socket_fd = start_listen(listen_adapter, listen_port, 5);

	clients[0] -> fd = -1;
	clients[1] -> fd = -1;

	for(;;)
	{
		fd_set rfds;
		FD_ZERO(&rfds);

		int max_fd = -1;

		FD_SET(listen_socket_fd, &rfds);
		max_fd = max(max_fd, listen_socket_fd);

		if (clients[0] -> fd != -1)
		{
			FD_SET(clients[0] -> fd, &rfds);
			max_fd = max(max_fd, clients[0] -> fd);
		}

		if (clients[1] -> fd != -1)
		{
			FD_SET(clients[1] -> fd, &rfds);
			max_fd = max(max_fd, clients[1] -> fd);
		}

		if (select(max_fd + 1, &rfds, NULL, NULL, NULL) == -1)
		{
			if (errno != EINTR)
				error_exit("select failed");

			continue;
		}

		if (clients[0] -> fd != -1 && FD_ISSET(clients[0] -> fd, &rfds))
		{
		}

		if (clients[1] -> fd != -1 && FD_ISSET(clients[1] -> fd, &rfds))
		{
		}

		if (FD_ISSET(listen_socket_fd, &rfds))
		{
			if (clients[0] -> fd != -1 && clients[1] -> fd != -1)
			{
				close(clients[0] -> fd);
				close(clients[1] -> fd);
				clients[0] -> fd = -1;
				clients[1] -> fd = -1;
			}

			struct sockaddr_in client_addr;
			socklen_t client_addr_len = sizeof(client_addr);
			int new_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&client_addr, &client_addr_len);

			std::string client_password;
			long long unsigned int challenge = 1;
			if (auth_eb(new_socket_fd, DEFAULT_COMM_TO, user_map, client_password, &challenge) == 0)
			{
// do a handshake like a broker would do
// broker-protocol also in a class
				proxy_client_t *pcp = NULL;

				if (clients[0] -> fd == -1)
					pcp = clients[0];
				else if (clients[1] -> fd == -1)
					pcp = clients[1];

				pcp -> fd = new_socket_fd;
				pcp -> password = client_password;
				pcp -> challenge = challenge;
			}
			else
			{
				close(new_socket_fd);
			}
		}
	}

	delete p;

	dolog(LOG_INFO, "Finished");

	return 0;
}
