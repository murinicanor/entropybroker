#include <string>
#include <map>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <openssl/blowfish.h>

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "auth.h"

const char *pid_file = PID_DIR "/server_egb.pid";

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

int open_unixdomain_socket(char *path)
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
		error_exit("Failed to create socket");

	if (connect(fd, (struct sockaddr *)&addr, len) == 0)
		return fd;

	error_exit("Failed to connect to %s", path);

	return -1;
}

void help(void)
{
        printf("-i host   entropy_broker-host to connect to\n");
	printf("-d path   unix domain socket to read from\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -i)\n");
	printf("-a x      bytes per interval to read from egd\n");
	printf("-b x      interval for reading data\n");
        printf("-l file   log to file 'file'\n");
        printf("-s        log to syslog\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
        printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	char *host = NULL;
	int port = 55225;
	int read_fd = -1;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *device = NULL;
	char *bytes_file = NULL;
	int read_interval = 5;
	unsigned int read_bytes_per_interval = 16;
	int index = 0;
	int verbose = 0;
	char server_type[128];
	bool show_bps = false;
	std::string username, password;

	fprintf(stderr, "eb_server_egb v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "hSX:P:a:b:o:i:d:l:snv")) != -1)
	{
		switch(c)
		{
			case 'S':
				show_bps = true;
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'v':
				verbose++;
				break;

			case 'a':
				read_bytes_per_interval = atoi(optarg);
				if (read_bytes_per_interval > sizeof(bytes))
					error_exit("-a: parameter must be %d or less", sizeof(bytes));
				break;

			case 'b':
				read_interval = atoi(optarg);
				break;

			case 'o':
				bytes_file = optarg;
				break;

			case 'i':
				host = optarg;
				break;

			case 'd':
				device = optarg;
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
		error_exit("username + password cannot be empty");

	if (!host && !bytes_file)
		error_exit("no host to connect to given");

	if (host != NULL && bytes_file != NULL)
		error_exit("-o and -d are mutual exclusive");

	if (chdir("/") == -1)
		error_exit("chdir(/) failed");
	(void)umask(0177);
	no_core();
	lock_mem(bytes, sizeof bytes);

	set_logging_parameters(log_console, log_logfile, log_syslog);

	protocol *p = new protocol(host, port, username, password, true, server_type);

	if (device)
		read_fd = open_unixdomain_socket(device);
	if (read_fd == -1)
		error_exit("error opening %s", device);

	snprintf(server_type, sizeof(server_type), "server_egb v" VERSION " %s", device);

	if (!do_not_fork)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	double cur_start_ts = get_ts();
	long int total_byte_cnt = 0;
	for(;;)
	{
		unsigned char request[2], reply[1];
		int bytes_to_read = min(255, min(sizeof(bytes) - index, read_bytes_per_interval));

		// gather random data from EGD
		request[0] = 1;
		request[1] = bytes_to_read;
		if (WRITE(read_fd, (char *)request, sizeof(request)) != 2)
			error_exit("Problem sending request to EGD");
		if (READ(read_fd, (char *)reply, 1) != 1)
			error_exit("Problem receiving reply header from EGD");
		bytes_to_read = reply[0];
		if (READ(read_fd, (char *)&bytes[index], bytes_to_read) != bytes_to_read)
			error_exit("Problem receiving reply-data from EGD");
		index += bytes_to_read;
		dolog(LOG_DEBUG, "Got %d bytes from EGD", bytes_to_read);
		////////

		if (index == sizeof(bytes))
		{
			if (bytes_file)
			{
				emit_buffer_to_file(bytes_file, bytes, index);
			}
			else
			{
				if (p -> message_transmit_entropy_data(bytes, index) == -1)
				{
					dolog(LOG_INFO, "connection closed");
					p -> drop();
				}
			}

			index = 0;
		}

		if (show_bps)
		{
			double now_ts = get_ts();

			total_byte_cnt += bytes_to_read;

			if ((now_ts - cur_start_ts) >= 1.0)
			{
				int diff_t = now_ts - cur_start_ts;

				printf("Total number of bytes: %ld, avg/s: %f\n", total_byte_cnt, (double)total_byte_cnt / diff_t);

				cur_start_ts = now_ts;
				total_byte_cnt = 0;
			}
		}

		if (index == 0 || bytes_to_read == 0)
		{
			if (p -> sleep_interruptable(read_interval) != 0)
			{
				dolog(LOG_INFO, "connection closed");
				p -> drop();
				continue;
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);
	unlink(pid_file);

	delete p;

	return 0;
}
