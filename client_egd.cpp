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

#include "error.h"
#include "utils.h"
#include "log.h"
#include "math.h"
#include "protocol.h"

#define DEFAULT_COMM_TO 15

void handle_client(int fd, char *host, int port)
{
	int socket_fd = -1;
	int will_get_n_bits, will_get_n_bytes;
	char recv_msg[8 + 1], reply[8 + 1];
	unsigned char egd_msg[2];
	int n_bits_to_get;

	if (READ(fd, (char *)egd_msg, 2) != 2)
	{
		dolog(LOG_INFO, "short read on EGD client");
		return;
	}

	// HANDLE OTHER MESSAGES AS WELL FIXME

	n_bits_to_get = egd_msg[1] * 8;
	if (n_bits_to_get <= 0)
	{
		dolog(LOG_CRIT, "number of bits to get <= 0: %d", n_bits_to_get);
		return;
	}
	if (n_bits_to_get > 9999)
		n_bits_to_get = 9999;

	dolog(LOG_INFO, "will get %d bits", n_bits_to_get);

	snprintf(recv_msg, sizeof(recv_msg), "0001%04d", n_bits_to_get);

	if (reconnect_server_socket(host, port, &socket_fd, "client_egd " VERSION, 0) == -1)
	{
		dolog(LOG_CRIT, "cannot connect to %s:%d", host, port);
		return;
	}
	dolog(LOG_DEBUG, "socket fd: %d", socket_fd);

	if (WRITE_TO(socket_fd, recv_msg, 8, DEFAULT_COMM_TO) != 8)
	{
		dolog(LOG_INFO, "write error to %s:%d", host, port);
		return;
	}

	dolog(LOG_DEBUG, "request sent");

	if (READ_TO(socket_fd, reply, 8, DEFAULT_COMM_TO) != 8)
	{
		dolog(LOG_INFO, "read error from %s:%d", host, port);
		return;
	}
	reply[8] = 0x00;
	dolog(LOG_DEBUG, "received reply: %s", reply);
	if (reply[0] == '9' && reply[1] == '0' && reply[2] == '0' && (reply[3] == '0' || reply[3] == '2'))
	{
		dolog(LOG_WARNING, "server has no data/quota");
		will_get_n_bits = 0;
	}
	else
	{
		will_get_n_bits = atoi(&reply[4]);
	}
	will_get_n_bytes = (will_get_n_bits + 7) / 8;

	dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

	if (will_get_n_bytes > 0)
	{
		unsigned char msg;
		char *buffer = (char *)malloc(will_get_n_bytes);
		if (!buffer)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);

		if (READ_TO(socket_fd, buffer, will_get_n_bytes, DEFAULT_COMM_TO) != will_get_n_bytes)
		{
			dolog(LOG_INFO, "read error from %s:%d", host, port);
			return;
		}

		// SEND TO EGD CLIENT FIXME
		msg = min(255, will_get_n_bytes);
		if (WRITE(fd, (char *)&msg, 1) != 1)
		{
			dolog(LOG_INFO, "short write on egd client (# bytes)");
			return;
		}

		if (WRITE(fd, buffer, msg) != msg)
		{
			dolog(LOG_INFO, "short write on egd client (data)");
			return;
		}

		free(buffer);
	}
	else
	{
		// SEND 0 BYTES TO EGD CLIENT FIXME
	}

	close(socket_fd);
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

	if (bind(fd, (struct sockaddr *)&addr, len) == -1)
		error_exit("bind failed");

	if (listen(fd, nListen) == -1)
		error_exit("listen failed");

	return fd;
}

void help(void)
{
	printf("-i host   eb-host to connect to\n");
	printf("-d file   unix domain socket\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
}

int main(int argc, char *argv[])
{
	char *host = NULL;
	int port = 55225;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *uds = NULL;
	int listen_fd, nListen = 5;

	printf("client_egd v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "d:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'd':
				uds = optarg;
				break;

			case 'i':
				host = optarg;
				break;

			case 's':
				log_syslog = 1;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = 1;
				log_console = 1;
				break;

			default:
				help();
				return 1;
		}
	}

	if (!host)
		error_exit("no host to connect to selected");

	if (!uds)
		error_exit("no path for the unix domain socket selected");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	listen_fd = open_unixdomain_socket(uds, nListen);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

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
				handle_client(fd, host, port);

				exit(0);
			}
			else if (pid == -1)
				error_exit("failed to fork");

			close(fd);
		}
	}

	dolog(LOG_INFO, "Finished");

	return 0;
}
