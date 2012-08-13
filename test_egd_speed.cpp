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
		error_exit("Failed to setup socket");

	if (connect(fd, (struct sockaddr *)&addr, len) == 0)
		return fd;

	error_exit("Failed to connect to %s", path);

	return -1;
}

void help(void)
{
	printf("-d file  unix domain socket to read from\n");
	printf("-i x     how long to read\n");
}

int main(int argc, char *argv[])
{
	int c;
	int bytes_read = 0;
	char *device = NULL;
	double start;
	int interval = 5;

	while((c = getopt(argc, argv, "hd:i:")) != -1)
	{
		switch(c)
		{
			case 'd':
				device = optarg;
				break;

			case 'i':
				interval = atoi(optarg);
				break;

			case 'h':
				help();
				return 0;

			default:
				error_exit("unknown parameter");
		}
	}

	if (device == NULL)
		error_exit("no socket selected, use -d");

	printf("Using device: %s\n", device);
	printf("Trying for %d seconds\n", interval);

	signal(SIGPIPE, SIG_IGN);

	start = get_ts();
	do
	{
		int bytes_to_read, read_fd;
		unsigned char request[2], reply;

		read_fd = open_unixdomain_socket(device);
		if (read_fd == -1)
			error_exit("error opening stream");

		// gather random data from EGD
		request[0] = 1;
		request[1] = 255;
		if (WRITE(read_fd, (char *)request, sizeof(request)) != 2)
			error_exit("Problem sending request to EGD");
		if (READ(read_fd, (char *)&reply, 1) != 1)
			error_exit("Problem receiving reply header from EGD");
		bytes_to_read = reply;
		if (bytes_to_read > 0)
		{
			char buffer[256];
			if (READ(read_fd, buffer, bytes_to_read) != bytes_to_read)
				error_exit("Problem receiving reply-data from EGD");
		}
		bytes_read += bytes_to_read;

		close(read_fd);
	}
	while((get_ts() - start) < interval);

	printf("%d bytes in %d seconds\n", bytes_read, interval);

	return 0;
}
