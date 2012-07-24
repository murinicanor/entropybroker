#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/select.h>
#include <netinet/tcp.h>

#include "error.h"
#include "log.h"
#include "kernel_prng_rw.h"

#define MAX_LRAND48_GETS 250

#define incopy(a)       *((struct in_addr *)a)

double get_ts(void)
{
	struct timeval ts;

	if (gettimeofday(&ts, NULL) == -1)
		error_exit("gettimeofday failed");

	return (((double)ts.tv_sec) + ((double)ts.tv_usec)/1000000.0);
}

int READ(int fd, char *whereto, size_t len)
{
	ssize_t cnt=0;

	while(len>0)
	{
		ssize_t rc;

		rc = read(fd, whereto, len);

		if (rc == -1)
		{
			if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
				return -1;
		}
		else if (rc == 0)
		{
			break;
		}
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

int READ_TO(int fd, char *whereto, size_t len, int to)
{
	double end_ts = get_ts() + (double)to;
	ssize_t cnt=0;

	while(len>0)
	{
		fd_set rfds;
		struct timeval tv;
		double now_ts = get_ts();
		double time_left = end_ts - now_ts;
		ssize_t rc;

		if (time_left <= 0.0)
			return -1;

		tv.tv_sec = time_left;
		tv.tv_usec = (time_left - (double)tv.tv_sec) * 1000000.0;

		FD_ZERO(&rfds);
		FD_SET(fd, &rfds);

		rc = select(fd + 1, &rfds, NULL, NULL, &tv);
		if (rc == -1)
		{
			if (errno == EINTR || errno == EINPROGRESS || errno == EAGAIN)
				continue;

			return -1;
		}
		else if (rc == 0)
		{
			return -1;
		}

		if (FD_ISSET(fd, &rfds))	// should always evaluate to true at this point
		{
			rc = read(fd, whereto, len);

			if (rc == -1)
			{
				if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
					return -1;
			}
			else if (rc == 0)
			{
				return -1;
			}
			else
			{
				whereto += rc;
				len -= rc;
				cnt += rc;
			}
		}
	}

	return cnt;
}

int WRITE(int fd, char *whereto, size_t len)
{
	ssize_t cnt=0;

	while(len>0)
	{
		ssize_t rc;

		rc = write(fd, whereto, len);

		if (rc == -1)
		{
			if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
				return -1;
		}
		else if (rc == 0)
		{
			return -1;
		}
		else
		{
			whereto += rc;
			len -= rc;
			cnt += rc;
		}
	}

	return cnt;
}

int WRITE_TO(int fd, char *whereto, size_t len, int to)
{
	double end_ts = get_ts() + (double)to;
	ssize_t cnt=0;

	while(len>0)
	{
		fd_set wfds;
		struct timeval tv;
		double now_ts = get_ts();
		double time_left = end_ts - now_ts;
		ssize_t rc;

		if (time_left <= 0.0)
			return -1;

		tv.tv_sec = time_left;
		tv.tv_usec = (time_left - (double)tv.tv_sec) * 1000000.0;

		FD_ZERO(&wfds);
		FD_SET(fd, &wfds);

		rc = select(fd + 1, NULL, &wfds, NULL, &tv);
		if (rc == -1)
		{
			if (errno == EINTR || errno == EINPROGRESS || errno == EAGAIN)
				continue;

			return -1;
		}
		else if (rc == 0)
		{
			return -1;
		}

		if (FD_ISSET(fd, &wfds))	// should always evaluate to true at this point
		{

			rc = write(fd, whereto, len);

			if (rc == -1)
			{
				if (errno != EINTR && errno != EINPROGRESS && errno != EAGAIN)
					return -1;
			}
			else if (rc == 0)
			{
				return -1;
			}
			else
			{
				whereto += rc;
				len -= rc;
				cnt += rc;
			}
		}
	}

	return cnt;
}

int start_listen(char *adapter, int portnr, int listen_queue_size)
{
	int reuse_addr = 1;
	struct sockaddr_in server_addr;
	int	server_addr_len;
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit("failed creating socket");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse_addr, sizeof(reuse_addr)) == -1)
		error_exit("setsockopt(SO_REUSEADDR) failed");

	server_addr_len = sizeof(server_addr);
	memset((char *)&server_addr, 0x00, server_addr_len);
	server_addr.sin_family = AF_INET;
	if (!adapter)
	{
		server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	}
	else
	{
		if (inet_aton(adapter, &server_addr.sin_addr) == 0)
			error_exit("inet_aton(%s) failed", adapter);
	}
	server_addr.sin_port = htons(portnr);

	if (bind(fd, (struct sockaddr *)&server_addr, server_addr_len) == -1)
		error_exit("bind() failed");

	if (listen(fd, listen_queue_size) == -1)
		error_exit("listen() failed");

	return fd;
}

int resolve_host(char *host, struct sockaddr_in *addr)
{
	struct hostent *hostdnsentries;

	hostdnsentries = gethostbyname(host);
	if (hostdnsentries == NULL)
	{
		switch(h_errno)
		{
			case HOST_NOT_FOUND:
				error_exit("The specified host is unknown.\n");
				break;

			case NO_ADDRESS:
				error_exit("The requested name is valid but does not have an IP address.\n");
				break;

			case NO_RECOVERY:
				error_exit("A non-recoverable name server error occurred.\n");
				break;

			case TRY_AGAIN:
				error_exit("A temporary error occurred on an authoritative name server. Try again later.\n");
				break;

			default:
				error_exit("Could not resolve %s for an unknown reason (%d)\n", host, h_errno);
		}

		return -1;
	}

	/* create address structure */
	addr -> sin_family = hostdnsentries -> h_addrtype;
	addr -> sin_addr = incopy(hostdnsentries -> h_addr_list[0]);

	return 0;
}

int connect_to(char *host, int portnr)
{
	int fd;
	struct sockaddr_in addr;

	/* resolve */
	memset(&addr, 0x00, sizeof(addr));
	resolve_host(host, &addr);
	addr.sin_port = htons(portnr);

	/* connect */
	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		error_exit("connect_to: problem creating socket");

	/* connect to peer */
	if (connect(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr)) == 0)
	{
		/* connection made, return */
		return fd;
	}

	close(fd);

	return -1;
}

void disable_nagle(int fd)
{
      int disable = 1;

      if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&disable, sizeof(disable)) == -1)
		error_exit("setsockopt(IPPROTO_TCP, TCP_NODELAY) failed");
}

void enable_tcp_keepalive(int fd)
{
	int keep_alive = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (char *)&keep_alive, sizeof(keep_alive)) == -1)
		error_exit("problem setting KEEPALIVE");
}

int myrand(int max)
{
	static int n_retrieved = MAX_LRAND48_GETS;

	if (--n_retrieved < 0)
	{
		unsigned short seed16v[3];

		kernel_rng_read_non_blocking((unsigned char *)seed16v, sizeof(seed16v));
		seed48(seed16v);

		n_retrieved = MAX_LRAND48_GETS;
	}

	return (int)(drand48() * (double)max);
}
