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
#include <openssl/blowfish.h>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "math.h"
#include "protocol.h"
#include "auth.h"
#include "kernel_prng_io.h"

#define DEFAULT_COMM_TO 15
const char *pid_file = PID_DIR "/client_egd.pid";
const char *client_type = "client_egd " VERSION;

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void egd_get__failure(int fd)
{
	unsigned char none = 0;

	if (WRITE(fd, (char *)&none, 1) != 1)
		dolog(LOG_INFO, "short write on egd client (# bytes)");
}

void egd_get(int fd, protocol *p, bool blocking)
{
	unsigned char n_bytes_to_get;

	if (READ(fd, (char *)&n_bytes_to_get, 1) != 1)
	{
		dolog(LOG_INFO, "short read on EGD client");
		return;
	}

	int n_bits_to_get = n_bytes_to_get * 8;

	dolog(LOG_INFO, "will get %d bits", n_bits_to_get);

	char *buffer = (char *)malloc(n_bytes_to_get);
	if (!buffer)
		error_exit("Out of memory");
	lock_mem(buffer, n_bytes_to_get);

	int n_bytes = p -> request_bytes(buffer, n_bits_to_get, !blocking);
	if (n_bytes == 0)
		egd_get__failure(fd);
	else
	{
		unsigned char msg = min(255, n_bytes);
		if (!blocking && WRITE(fd, (char *)&msg, 1) != 1)
			dolog(LOG_INFO, "short write on egd client (# bytes)");
		else if (WRITE(fd, (char *)buffer, msg) != msg)
			dolog(LOG_INFO, "short write on egd client (data)");

		memset(buffer, 0x00, n_bytes);
	}

	unlock_mem(buffer, n_bytes);
	free(buffer);
}

void egd_entropy_count(int fd)
{
	unsigned int count = 9999;
	unsigned char reply[] = { (count >> 24) & 255, (count >> 16) & 255, (count >> 8) & 255, count & 255 };

	if (WRITE(fd, (char *)reply, 4) != 4)
		dolog(LOG_INFO, "short write on egd client");
}

void egd_put(int fd, protocol *p)
{
	unsigned char cmd[3];
	if (READ(fd, (char *)cmd, 3) != 3)
	{
		dolog(LOG_INFO, "EGD_put short read (1)");
		return;
	}

	int bit_cnt = (cmd[0] << 8) + cmd[1];
	dolog(LOG_INFO, "EGD client puts %d bits of entropy", bit_cnt);

	unsigned char byte_cnt = cmd[2];

	char buffer[256];
	lock_mem(buffer, sizeof buffer);
	if (byte_cnt > 0 && READ(fd, buffer, byte_cnt) != byte_cnt)
	{
		dolog(LOG_INFO, "EGD_put short read (2)");
		return;
	}

	int socket_fd = -1;
	(void)p -> message_transmit_entropy_data((unsigned char *)buffer, byte_cnt);

	memset(buffer, 0x00, sizeof buffer);
	unlock_mem(buffer, sizeof buffer);

	close(socket_fd);
}

void handle_client(int fd, protocol *p)
{
	unsigned char egd_msg;

	if (READ(fd, (char *)&egd_msg, 1) != 1)
	{
		dolog(LOG_INFO, "short read on EGD client");
		return;
	}

	if (egd_msg == 0)	// get entropy count
		egd_entropy_count(fd);
	else if (egd_msg == 1)	// get data, non blocking
		egd_get(fd, p, false);
	else if (egd_msg == 2)	// get data, blocking
		egd_get(fd, p, true);
	else if (egd_msg == 3)	// put data
		egd_put(fd, p);
}

int open_unixdomain_socket(char *path, int nListen)
{
	int len;
	struct sockaddr_un addr;
	int fd = -1;

	if (strlen(path) >= sizeof(addr.sun_path))
		error_exit("Path %s too large (%d limit)", path, sizeof(addr.sun_path));

	memset(&addr, 0x00, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);
	len = offsetof(struct sockaddr_un, sun_path) + strlen(path);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit("socket creation failed");

	if (bind(fd, (struct sockaddr *)&addr, len) == -1)
		error_exit("bind failed");

	if (listen(fd, nListen) == -1)
		error_exit("listen failed");

	return fd;
}

void help(void)
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-d file   unix domain socket\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	char *host = NULL;
	int port = 55225;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *uds = NULL;
	int listen_fd, nListen = 5;
	std::string username, password;

	printf("eb_client_egd v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "hX:P:d:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'd':
				uds = optarg;
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

			default:
				help();
				return 1;
		}
	}

	if (password.length() == 0 || username.length() == 0)
		error_exit("please set a non-empty username + password");

	if (!host)
		error_exit("no host to connect to selected");

	if (!uds)
		error_exit("no path for the unix domain socket selected");

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0177);
	no_core();

	set_logging_parameters(log_console, log_logfile, log_syslog);

	protocol *p = new protocol(host, port, username, password, false, client_type);

	listen_fd = open_unixdomain_socket(uds, nListen);

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

	for(;;)
	{
		struct sockaddr addr;
		socklen_t addr_len = sizeof(addr);
		int fd = accept(listen_fd, &addr, &addr_len);

		if (fd != -1)
		{
			pid_t pid = 0;

			if (!do_not_fork)
				pid = fork();

			if (pid == 0)
			{
				handle_client(fd, p);

				if (!do_not_fork)
					exit(0);
			}
			else if (pid == -1)
				error_exit("failed to fork");

			close(fd);
		}
	}

	unlink(pid_file);
	dolog(LOG_INFO, "Finished");

	return 0;
}
