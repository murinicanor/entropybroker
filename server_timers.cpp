#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

const char *server_type = "server_timers v" VERSION;

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"

double gen_entropy_data(void)
{
	double start;

	start = get_ts();

	/* arbitrary value:
	 * not too small so that there's room for noise
	 * not too large so that we don't sleep unnecessary
	 */
	usleep(100);

	return get_ts() - start;
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1240];
	unsigned char byte;
	int bits = 0, index = 8;
	char *host = (char *)"localhost";
	int port = 55225;
	int socket_fd = -1;

	signal(SIGPIPE, SIG_IGN);

//	printf("timer_entropyd v" VERSION ", (C) 2009 by folkert@vanheusden.com\n\n");

//	if (daemon(-1, -1) == -1)
//		error_exit("failed to become daemon process");

	sprintf((char *)bytes, "0002%04d", (int)(sizeof(bytes) - 8) * 8);

	for(;;)
	{
		double t1, t2;

		if (reconnect_server_socket(host, port, &socket_fd, server_type) == -1)
			continue;

		// gather random data

		t1 = gen_entropy_data(), t2 = gen_entropy_data();

		if (t1 == t2)
			continue;

		byte <<= 1;
		if (t1 > t2)
			byte |= 1;

		if (++bits == 8)
		{
			bytes[index++] = byte;
			bits = 0;

			if (index == sizeof(bytes))
			{
				int value;
				char reply[8 + 1];

				dolog(LOG_DEBUG, "request to send %d bytes", sizeof(bytes) - 8);

				// header
				if (WRITE(socket_fd, (char *)bytes, 8) != 8)
				{
					dolog(LOG_INFO, "connection closed");
					close(socket_fd);
					socket_fd = -1;
					continue;
				}

				// ack from server?
				if (READ(socket_fd, reply, 8) != 8)
				{
					dolog(LOG_INFO, "connection closed");
					close(socket_fd);
					socket_fd = -1;
					continue;
				}

				value = atoi(&reply[4]);
				reply[4] = 0x00;

				if (value <= 0)
					error_exit("value %d less then 1", value);

				if (strcmp(reply, "0001") == 0)			// ACK
				{
					int cur_n_bytes = (value + 7) / 8;

					dolog(LOG_DEBUG, "Transmitting %d bytes to %s:%d", cur_n_bytes, host, port);

					if (WRITE(socket_fd, (char *)&bytes[8], cur_n_bytes) != cur_n_bytes)
					{
						dolog(LOG_INFO, "connection closed");
						close(socket_fd);
						socket_fd = -1;
						continue;
					}
				}
				else if (strcmp(reply, "9001") == 0)		// NACK
				{
					dolog(LOG_DEBUG, "pool full, sleeping %d seconds", value);

					sleep(value);
				}
				else
					error_exit("garbage received: %s", reply);

				index = 8; // skip header
			}
		}
	}

	return 0;
}
