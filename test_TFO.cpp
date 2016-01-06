#include <stdio.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/socket.h>

int main(int argc, char *argv[])
{
	int fd = 0;
	int qlen = 5;

	setsockopt(fd, SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));

	return 0;
}
