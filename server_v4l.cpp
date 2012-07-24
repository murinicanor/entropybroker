#include <errno.h>
#include <fcntl.h>
#include <linux/videodev2.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "error.h"
#include "log.h"
#include "protocol.h"
#include "server_utils.h"
#include "utils.h"

const char *server_type = "server_v4l v" VERSION;

#define RES_LOW  0
#define RES_HIGH 127

void open_dev(char *dev_name, int *fd, unsigned char **io_buffer, int *io_buffer_len)
{
	*fd = open(dev_name, O_RDWR);
	if (*fd == -1)
		return;

	struct v4l2_capability cap;
	memset(&cap, 0x00, sizeof(cap));
	if (ioctl(*fd, VIDIOC_QUERYCAP, &cap) == -1)
		error_exit("Cannot VIDIOC_QUERYCAP");
	else
	{
		printf("Device %s is:\n", dev_name);
		printf(" %s %s %s\n", cap.driver, cap.card, cap.bus_info);
		printf(" version: %d %d %d\n", (cap.version >> 16) & 255, (cap.version >> 8) & 255, cap.version & 255);
		if ((cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) == 0)
			error_exit("Video4linux device cannot capture video");
	}

	struct v4l2_format fmt;
	memset(&fmt, 0x00, sizeof(fmt));
	fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUV420;
	if (ioctl(*fd, VIDIOC_G_FMT, &fmt) == -1)
		error_exit("ioctl(VIDIOC_G_FMT) failed");
	char format[5];
	memcpy(format, &fmt.fmt.pix.pixelformat, 4);
	format[4]=0x00;
	printf(" %dx%d: %d/%s\n", fmt.fmt.pix.width, fmt.fmt.pix.height, fmt.type, format);
	fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(*fd, VIDIOC_S_FMT, &fmt) == -1)
		error_exit("ioctl(VIDIOC_S_FMT) failed");

	struct v4l2_requestbuffers req;
	memset(&req, 0x00, sizeof(req));
	req.count  = 1;
	req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	req.memory = V4L2_MEMORY_MMAP;
	if (ioctl(*fd, VIDIOC_REQBUFS, &req) == -1)
		error_exit("ioctl(VIDIOC_REQBUFS) failed");

	struct v4l2_buffer buf;
	memset(&buf, 0x00, sizeof(buf));
	buf.type        = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf.memory      = V4L2_MEMORY_MMAP;
	buf.index       = 0;
	if (ioctl(*fd, VIDIOC_QUERYBUF, &buf) == -1)
		error_exit("ioctl(VIDIOC_QUERYBUF) failed");

	if (ioctl(*fd, VIDIOC_QBUF, &buf) == -1)
		error_exit("ioctl(VIDIOC_QBUF) failed");

	enum v4l2_buf_type buf_type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(*fd, VIDIOC_STREAMON, &buf_type) == -1)
		error_exit("ioctl(VIDIOC_STREAMON) failed");

	*io_buffer_len = buf.length;
	*io_buffer = static_cast<unsigned char *>(mmap(NULL, buf.length, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, buf.m.offset));
}

void close_device(int fd, unsigned char *p, int p_len)
{
	munmap(p, p_len);

	close(fd);
}

void take_picture(int fd, struct v4l2_buffer *buf)
{
	ioctl(fd, VIDIOC_DQBUF, buf);
}

void untake_picture(int fd, struct v4l2_buffer *buf)
{
	ioctl(fd, VIDIOC_QBUF, buf);
}

void help(void)
{
	printf("-i host   eb-host to connect to\n");
	printf("-d x   device to use\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -d)\n");
	printf("-f x   skip x frames before processing images (in case the device\n");
	printf("       needs a few frames to settle)\n");
	printf("-l file   log to file 'file'\n");
	printf("-s        log to syslog\n");
	printf("-n     do not fork\n");
}

int main(int argc, char *argv[])
{
	int device_settle = 25;
	int c;
	char *host = NULL;
	int port = 55225;
	unsigned char *img1, *img2, *unbiased;
	int nunbiased = 0;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *device = NULL;
	unsigned char byte; // NO NEED FOR INITIALIZATION
	int nbits = 0;
	int socket_fd = -1;
	char *bytes_file = NULL;
	int loop;

	fprintf(stderr, "%s, (C) 2009-2012 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "f:o:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'f':
				device_settle = atoi(optarg);
				if (device_settle < 0)
					error_exit("-f requires a value >= 0");
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

			default:
				help();
				return 1;
		}
	}

	if (!host && !bytes_file)
		error_exit("no host to connect to given");

	if (host != NULL && bytes_file != NULL)
		error_exit("-o and -d are mutual exclusive");

	if (!device)
		error_exit("Please select a video4linux video device (e.g. a webcam, tv-card, etc.)");

	set_logging_parameters(log_console, log_logfile, log_syslog);

	if (!do_not_fork)
	{
		if (daemon(-1, -1) == -1)
			error_exit("fork failed");
	}

	/* open device */
	int fd = -1;
	unsigned char *io_buffer = NULL;
	int io_buffer_len = -1;
	open_dev(device, &fd, &io_buffer, &io_buffer_len);
	if (fd == -1)
		error_exit("failure opening %s", device);

	/* let device settle */
	dolog(LOG_DEBUG, "waiting for device to settle");
	struct v4l2_buffer buf;
	memset(&buf, 0x00, sizeof(buf));
	buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	buf.memory = V4L2_MEMORY_MMAP;
	for(loop=0; loop<device_settle; loop++)
	{
		take_picture(fd, &buf);
		untake_picture(fd, &buf);
	}

	for(;;)
	{
		if (!bytes_file)
		{
			if (reconnect_server_socket(host, port, &socket_fd, server_type, 1) == -1)
				continue;

			disable_nagle(socket_fd);
			enable_tcp_keepalive(socket_fd);
		}

		img1 = (unsigned char *)malloc(io_buffer_len);
		img2 = (unsigned char *)malloc(io_buffer_len);
		unbiased = (unsigned char *)malloc(io_buffer_len);
		if (!img1 || !img2 || !unbiased)
			error_exit("out of memory");

		/* take pictures */
		dolog(LOG_DEBUG, "Smile!");
		memset(&buf, 0x00, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		take_picture(fd, &buf);
		memcpy(img1, io_buffer, io_buffer_len);
		untake_picture(fd, &buf);
		//
		memset(&buf, 0x00, sizeof(buf));
		buf.type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
		buf.memory = V4L2_MEMORY_MMAP;
		take_picture(fd, &buf);
		memcpy(img2, io_buffer, io_buffer_len);
		untake_picture(fd, &buf);

		/* unbiase */
		dolog(LOG_DEBUG, "Filtering...");
		nunbiased=0;
		for(loop=0; loop<io_buffer_len; loop+=2)
		{
			/* calculate difference between the images */
			int diff1 = abs(img2[loop + 0] - img1[loop + 0]);
			int diff2 = abs(img2[loop + 1] - img1[loop + 1]);

			/* if the 2 difference are not correlated, add bit */
			if ((diff1 & 1) != (diff2 & 1))
			{
				byte <<= 1;

				if (diff1 & 1)
					byte |= 1;

				nbits++;

				if (nbits == 8)
				{
					unbiased[nunbiased++] = byte;

					if (nunbiased == 1249)
						break;

					nbits = 0;
				}
			}
		}

		free(img2);
		free(img1);

		dolog(LOG_DEBUG, "got %d bytes of entropy", nunbiased);

		if (nunbiased > 0)
		{
			if (bytes_file)
			{
				emit_buffer_to_file(bytes_file, unbiased, nunbiased);
			}
			else
			{
				if (message_transmit_entropy_data(socket_fd, unbiased, nunbiased) == -1)
				{
					dolog(LOG_INFO, "connection closed");
					close(socket_fd);
					socket_fd = -1;
				}
			}
		}

		free(unbiased);
	}

	dolog(LOG_DEBUG, "Cleaning up");
	close_device(fd, io_buffer, io_buffer_len);

	return 0;
}
