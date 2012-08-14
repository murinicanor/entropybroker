#include <unistd.h>
#include <signal.h>
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
#include <time.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <sys/mman.h>
#include <sys/resource.h>

#include "error.h"
#include "log.h"
#include "kernel_prng_rw.h"
#include "my_pty.h"

#define MAX_LRAND48_GETS 250

#define incopy(a)       *((struct in_addr *)a)

long double get_ts_ns()
{
	struct timespec ts;

	if (clock_gettime(CLOCK_REALTIME, &ts) == -1)
		error_exit("clock_gettime() failed");

	// start time is removed to allow more bits 'behind the dot'
	return (long double)(ts.tv_sec) + (long double)(ts.tv_nsec) / 1000000000.0;
}

double get_ts()
{
	return (double)get_ts_ns();
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

int READ_TO(int fd, char *whereto, size_t len, double to)
{
	double end_ts = get_ts() + to;
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
			return 0;
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

int WRITE_TO(int fd, char *whereto, size_t len, double to)
{
	double end_ts = get_ts() + to;
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

void check_rand_state()
{
	static int n_random_retrieved = 0;

	if (--n_random_retrieved < 0)
	{
		unsigned short seed16v[3];

		kernel_rng_read_non_blocking((unsigned char *)seed16v, sizeof(seed16v));
		seed48(seed16v);

		n_random_retrieved = MAX_LRAND48_GETS;
	}
}

double mydrand()
{
	check_rand_state();

	return drand48();
}

int myrand()
{
	check_rand_state();

	return lrand48();
}

int myrand(int max)
{
	check_rand_state();

	return (int)(drand48() * (double)max);
}

void write_pid(const char *file)
{
	FILE *fh = fopen(file, "w");
	if (!fh)
		error_exit("Failed to write PID-file %s", file);

	fprintf(fh, "%d\n", getpid());

	fclose(fh);
}

void close_fds()
{
	for(int fd=3; fd<50; fd++)
		close(fd);
}

void start_process(char *shell, char *cmd, int *fd, pid_t *pid)
{
	int fd_slave;

	/* allocate pseudo-tty & fork*/
	*pid = get_pty_and_fork(fd, &fd_slave);
	if (*pid == -1)
		error_exit("Cannot fork and allocate pty");

	/* child? */
	if (*pid == 0)
	{
		setsid();

		/* reset signal handler for SIGTERM */
		signal(SIGTERM, SIG_DFL);

		/* connect slave-fd to stdin/out/err */
		close(0);
		close(1);
		close(2);
		dup(fd_slave);
		dup(fd_slave);
		dup(fd_slave);
		close_fds();

		/* start process */
		if (-1 == execlp(shell, shell, "-c", cmd, (void *)NULL))
			error_exit("cannot execlp(%s -c '%s')", shell, cmd);

		exit(1);
	}

	close(fd_slave);
}

void no_core()
{
#ifndef _DEBUG
	struct rlimit rlim = { 0, 0 };
	if (setrlimit(RLIMIT_CORE, &rlim) == -1)
		error_exit("setrlimit(RLIMIT_CORE) failed");
#endif
}

void lock_mem(void *p, int size)
{
	static bool notified_err = false;

	if (mlock(p, size) == -1)
	{
		if (!notified_err)
		{
			dolog(LOG_WARNING, "mlock failed");

			notified_err = true;
		}
	}
}

void unlock_mem(void *p, int size)
{
	static bool notified_err = false;

	if (munlock(p, size) == -1)
	{
		if (!notified_err)
		{
			dolog(LOG_CRIT, "mlock failed");

			notified_err = true;
		}
	}
}
