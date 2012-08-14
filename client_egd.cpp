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

void egd_get(int fd, char *host, int port, bool blocking, char *password)
{
	unsigned char dummy;

	if (READ(fd, (char *)&dummy, 1) != 1)
	{
		dolog(LOG_INFO, "short read on EGD client");
		return;
	}

	int n_bits_to_get = dummy * 8;
	if (n_bits_to_get <= 0)
	{
		dolog(LOG_CRIT, "number of bits to get <= 0: %d", n_bits_to_get);
		return;
	}
	if (n_bits_to_get > 9999)
		n_bits_to_get = 9999;

	dolog(LOG_INFO, "will get %d bits", n_bits_to_get);

	char get_msg[8 + 1];
	snprintf(get_msg, sizeof(get_msg), "0001%04d", n_bits_to_get);

	int socket_fd = -1;
	bool send_request = true;
	double last_msg = 0.0;
	for(;;)
	{
		double now = get_ts();

		if (socket_fd == -1)
		{
			dolog(LOG_INFO, "(re-)connecting to %s:%d", host, port);

			if (reconnect_server_socket(host, port, password, &socket_fd, client_type, 0) == -1)
			{
				dolog(LOG_CRIT, "cannot connect to %s:%d", host, port);
				send_request = true;
				continue;
			}

			last_msg = now;

			dolog(LOG_INFO, "Connected, fd: %d", socket_fd);
		}

		if (socket_fd == -1 && !blocking)
		{
			egd_get__failure(fd);
			return;
		}

		if (send_request)
		{
			dolog(LOG_DEBUG, "Request for %d bits", n_bits_to_get);

			if (WRITE_TO(socket_fd, get_msg, 8, DEFAULT_COMM_TO) != 8)
			{
				dolog(LOG_INFO, "write error to %s:%d", host, port);
				close(socket_fd);
				socket_fd = -1;
				send_request = true;
				continue;
			}

			last_msg = now;
		}

		dolog(LOG_DEBUG, "request sent");

		double sleep = (last_msg + TCP_SILENT_FAIL_TEST_INTERVAL) - now;
		if (sleep <= 0.0)
			sleep = 1.0;

		char reply[8 + 1];
		int rc = READ_TO(socket_fd, reply, 8, send_request ? DEFAULT_COMM_TO : sleep);
		if (rc == 0)
			send_request = true;
		else if (rc != 8)
		{
			dolog(LOG_INFO, "read error from %s:%d", host, port);
			close(socket_fd);
			socket_fd = -1;
			send_request = true;
			continue;
		}
		reply[8] = 0x00;

		last_msg = now;

		dolog(LOG_DEBUG, "received reply: %s", reply);

		if (memcmp(reply, "9000", 4) == 0 || memcmp(reply, "9002", 4) == 0)
		{
			dolog(LOG_WARNING, "server has no data/quota");

			send_request = false;

			if (!blocking)
			{
				egd_get__failure(fd);
				return;
			}

			continue;
		}
		else if (memcmp(reply, "0004", 4) == 0)       /* ping request */
		{
			static int pingnr = 0;
			char xmit_buffer[8 + 1];

			snprintf(xmit_buffer, sizeof(xmit_buffer), "0005%04d", pingnr++);

			dolog(LOG_DEBUG, "PING");

			if (WRITE_TO(socket_fd, xmit_buffer, 8, DEFAULT_COMM_TO) != 8)
			{
				close(socket_fd);
				socket_fd = -1;
			}

			send_request = true;
			continue;
		}
		else if (memcmp(reply, "0007", 4) == 0)  /* kernel entropy count */
		{
			char xmit_buffer[128], val_buffer[128];

			snprintf(val_buffer, sizeof(val_buffer), "%d", kernel_rng_get_entropy_count());
			snprintf(xmit_buffer, sizeof(xmit_buffer), "0008%04d%s", (int)strlen(val_buffer), val_buffer);

			dolog(LOG_DEBUG, "Send kernel entropy count");

			if (WRITE_TO(socket_fd, xmit_buffer, strlen(xmit_buffer), DEFAULT_COMM_TO) != (int)strlen(xmit_buffer))
			{
				close(socket_fd);
				socket_fd = -1;
			}

			send_request = true;
			continue;
		}
		else if (memcmp(reply, "0009", 4) == 0)
		{
			// broker has data!
			dolog(LOG_INFO, "Broker informs about data");

			send_request = true;
			continue;
		}

		int will_get_n_bits = atoi(&reply[4]);
		int will_get_n_bytes = (will_get_n_bits + 7) / 8;

		dolog(LOG_INFO, "server is offering %d bits (%d bytes)", will_get_n_bits, will_get_n_bytes);

		if (will_get_n_bytes == 0)
		{
			dolog(LOG_CRIT, "Broker is offering 0 bits?! Please report this to folkert@vanheusden.com");
			send_request = true;
			continue;
		}

		unsigned char *buffer_in = (unsigned char *)malloc(will_get_n_bytes);
		if (!buffer_in)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);
		unsigned char *buffer_out = (unsigned char *)malloc(will_get_n_bytes);
		if (!buffer_out)
			error_exit("out of memory allocating %d bytes", will_get_n_bytes);

		if (READ_TO(socket_fd, (char *)buffer_in, will_get_n_bytes, DEFAULT_COMM_TO) != will_get_n_bytes)
		{
			dolog(LOG_INFO, "Read error from %s:%d", host, port);

			free(buffer_out);
			free(buffer_in);

			close(socket_fd);
			socket_fd = -1;

			send_request = true;
			continue;
		}
		else
		{
			decrypt(buffer_in, buffer_out, will_get_n_bytes);

			unsigned char msg = min(255, will_get_n_bytes);
			if (!blocking && WRITE(fd, (char *)&msg, 1) != 1)
				dolog(LOG_INFO, "short write on egd client (# bytes)");
			else if (WRITE(fd, (char *)buffer_out, msg) != msg)
				dolog(LOG_INFO, "short write on egd client (data)");
		}

		free(buffer_out);
		free(buffer_in);

		break;
	}

	close(socket_fd);
}

void egd_entropy_count(int fd)
{
	unsigned int count = 9999;
	unsigned char reply[] = { (count >> 24) & 255, (count >> 16) & 255, (count >> 8) & 255, count & 255 };

	if (WRITE(fd, (char *)reply, 4) != 4)
		dolog(LOG_INFO, "short write on egd client");
}

void egd_put(int fd, char *host, int port, char *password)
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
	if (READ(fd, buffer, byte_cnt) != byte_cnt)
	{
		dolog(LOG_INFO, "EGD_put short read (2)");
		return;
	}

	int socket_fd = -1;
	(void)message_transmit_entropy_data(host, port, &socket_fd, password, client_type, (unsigned char *)buffer, byte_cnt);

	close(socket_fd);
}

void handle_client(int fd, char *host, int port, char *password)
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
		egd_get(fd, host, port, false, password);
	else if (egd_msg == 2)	// get data, blocking
		egd_get(fd, host, port, true, password);
	else if (egd_msg == 3)	// put data
		egd_put(fd, host, port, password);
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
	printf("-X file   read password from file\n");
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
	char *password = NULL;

	printf("eb_client_egd v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "X:P:d:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'X':
				password = get_password_from_file(optarg);
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

	if (!password)
		error_exit("no password set");

	if (!host)
		error_exit("no host to connect to selected");

	if (!uds)
		error_exit("no path for the unix domain socket selected");

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0122);
	lock_memory();

	set_logging_parameters(log_console, log_logfile, log_syslog);

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
				handle_client(fd, host, port, password);

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
