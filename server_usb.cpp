#include <string>
#include <map>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/blowfish.h>

extern "C" {
#include <libusb-1.0/libusb.h>
}

const char *server_type = "server_usb v" VERSION;
const char *pid_file = PID_DIR "/server_usb.pid";

#include "error.h"
#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "users.h"
#include "auth.h"

void poke(libusb_device_handle *dev)
{
	unsigned char buffer[256];

	(void)libusb_get_descriptor(dev, 0, 0, buffer, sizeof buffer);
}

long int timed_poke(libusb_device_handle *dev)
{
	struct timespec t1, t2;

	clock_gettime(CLOCK_REALTIME, &t1);
	poke(dev);
	clock_gettime(CLOCK_REALTIME, &t2);

	long int dummy = t2.tv_sec - t1.tv_sec;

	return (dummy * 1000000000 + t2.tv_nsec) - t1.tv_nsec;
}

double gen_entropy_data(libusb_device_handle *dev)
{
	return double(timed_poke(dev));
}

void sig_handler(int sig)
{
	fprintf(stderr, "Exit due to signal %d\n", sig);
	unlink(pid_file);
	exit(0);
}

void help(void)
{
	printf("-i host   entropy_broker-host to connect to\n");
	printf("-x port   port to connect to (default: %d)\n", DEFAULT_BROKER_PORT);
	printf("-o file   file to write entropy data to\n");
	printf("-S        show bps (mutual exclusive with -n)\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n        do not fork\n");
	printf("-P file   write pid to file\n");
	printf("-X file   read username+password from file\n");
}

int main(int argc, char *argv[])
{
	unsigned char bytes[1249];
	unsigned char byte = 0;
	int bits = 0;
	char *host = NULL;
	int port = DEFAULT_BROKER_PORT;
	int c;
	bool do_not_fork = false, log_console = false, log_syslog = false;
	char *log_logfile = NULL;
	char *bytes_file = NULL;
	bool show_bps = false;
	std::string username, password;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "x:hX:P:So:i:l:sn")) != -1)
	{
		switch(c)
		{
			case 'x':
				port = atoi(optarg);
				if (port < 1)
					error_exit("-x requires a value >= 1");
				break;

			case 'X':
				get_auth_from_file(optarg, username, password);
				break;

			case 'P':
				pid_file = optarg;
				break;

			case 'S':
				show_bps = true;
				break;

			case 'o':
				bytes_file = optarg;
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

			case 'h':
				help();
				return 0;

			default:
				help();
				return 1;
		}
	}

	if (host && (username.length() == 0 || password.length() == 0))
		error_exit("username + password cannot be empty");

	if (!host && !bytes_file && !show_bps)
		error_exit("no host to connect to, to file to write to and no 'show bps' given");

	(void)umask(0177);
	no_core();
	lock_mem(bytes, sizeof bytes);

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork && !show_bps)
	{
		if (daemon(0, 0) == -1)
			error_exit("fork failed");
	}

	write_pid(pid_file);

	protocol *p = NULL;
	if (host)
		p = new protocol(host, port, username, password, true, server_type);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, sig_handler);
	signal(SIGINT , sig_handler);
	signal(SIGQUIT, sig_handler);

	struct libusb_device **devs = NULL;
	libusb_device_handle **devhs;
	int index = 0, n = 0, use_n = 0;

	if (libusb_init(NULL) < 0)
		error_exit("cannot init libusb");

	if (libusb_get_device_list(NULL, &devs) < 0)
		error_exit("cannot retrieve usb devicelist");

	while(devs[n] != NULL) { n++; }

	dolog(LOG_INFO, "Found %d devices", n);

	devhs = (libusb_device_handle **)malloc(sizeof(libusb_device_handle *) * n);
	for(index=0; index<n; index++)
	{
		uint8_t bus_nr = libusb_get_bus_number(devs[index]);
		uint8_t dev_nr = libusb_get_device_address(devs[index]);
		int speed = libusb_get_device_speed(devs[index]);
		struct libusb_device_descriptor desc;
		libusb_get_device_descriptor(devs[index], &desc);

		dolog(LOG_INFO, "Opening device %d: %d/%d (%d) %04x:%04x", index, bus_nr, dev_nr, speed, desc.idVendor, desc.idProduct);

		if (desc.idVendor == 0x1d6b) // ignore
			continue;

		if (libusb_open(devs[index], &devhs[use_n++]) != 0)
			error_exit("error getting usb handle");
	}

	dolog(LOG_INFO, "Using %d devices", use_n);
	if (use_n == 0)
		error_exit("no devices found which can be used");

	long int total_byte_cnt = 0;
	double cur_start_ts = get_ts();
	int dev_index = 0;
	for(;;)
	{
		// gather random data
		double t1 = gen_entropy_data(devhs[dev_index]), t2 = gen_entropy_data(devhs[dev_index]);

		if (++dev_index >= use_n)
			dev_index = 0;

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
				if (bytes_file)
					emit_buffer_to_file(bytes_file, bytes, index);

				if (host && p -> message_transmit_entropy_data(bytes, index) == -1)
				{
					dolog(LOG_INFO, "connection closed");
					p -> drop();
				}

				index = 0; // skip header
			}

			if (show_bps)
			{
				double now_ts = get_ts();

				total_byte_cnt++;

				if ((now_ts - cur_start_ts) >= 1.0)
				{
					int diff_t = now_ts - cur_start_ts;

					printf("Number of bytes: %ld, avg/s: %f\n", total_byte_cnt, (double)total_byte_cnt / diff_t);

					cur_start_ts = now_ts;
					total_byte_cnt = 0;
				}
			}
		}
	}

	memset(bytes, 0x00, sizeof bytes);

	for(index=0; index<n; index++)
		libusb_close(devhs[index]);

	libusb_free_device_list(devs, 1);

	libusb_exit(NULL);

	free(devhs);

	unlink(pid_file);

	return 0;
}
