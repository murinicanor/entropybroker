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

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "auth.h"

const char *pid_file = PID_DIR "/server_egb.pid";
char *password = NULL;

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
	printf("-X file   read password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	char *host = NULL;
	int port = 55225;
	int socket_fd = -1;
	int read_fd = -1;
	int c;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *device = NULL;
	char *bytes_file = NULL;
	int read_interval = 5;
	unsigned int read_bytes_per_interval = 16;
	int index = 0;
	int verbose = 0;
	char server_type[128];
	bool show_bps = false;

	fprintf(stderr, "eb_server_egb v" VERSION ", (C) 2009-2012 by folkert@vanheusden.com\n");

	while((c = getopt(argc, argv, "hSX:P:a:b:o:i:d:l:snv")) != -1)
	{
		switch(c)
		{
			case 'S':
				show_bps = true;
				break;

			case 'X':
				password = get_password_from_file(optarg);
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
				log_syslog = 1;
				break;

			case 'l':
				log_logfile = optarg;
				break;

			case 'n':
				do_not_fork = 1;
				log_console = 1;
				break;

			case 'h':
				help();
				return 0;

			default:
				help();
				return 1;
		}
	}

	if (!password)
		error_exit("no password set");
	set_password(password);

	if (!host && !bytes_file)
		error_exit("no host to connect to given");

	if (host != NULL && bytes_file != NULL)
		error_exit("-o and -d are mutual exclusive");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (device)
		read_fd = open_unixdomain_socket(device);
	if (read_fd == -1)
		error_exit("error opening %s", device);

	snprintf(server_type, sizeof(server_type), "server_egb v" VERSION " %s", device);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
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
				if (message_transmit_entropy_data(host, port, &socket_fd, password, server_type, bytes, index) == -1)
				{
					dolog(LOG_INFO, "connection closed");

					close(socket_fd);
					socket_fd = -1;
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
			if (socket_fd != -1 && sleep_interruptable(socket_fd, read_interval) != 0)
			{
				dolog(LOG_INFO, "connection closed");

				close(socket_fd);
				socket_fd = -1;

				continue;
			}
		}
	}

	unlink(pid_file);

	return 0;
}
