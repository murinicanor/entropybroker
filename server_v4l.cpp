#include <errno.h>
#include <fcntl.h>
#include <linux/videodev.h>
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

const char *server_type = "server_v4l v" VERSION;

#define RES_LOW  0
#define RES_HIGH 127

typedef struct
{
	struct video_picture vidpic;
	struct video_window vidwin;
	struct video_mbuf vidmbuf;
	struct video_mmap vidmmap;
	struct video_capability vidcap;

	int fd;

	unsigned char *img;
} vconfig;

int open_device(vconfig *vconf, char *dev_name, char res)
{
	vconf -> fd = open(dev_name, O_RDONLY);
	if (vconf -> fd == -1)
		error_exit("error opening device %s", dev_name);

	/* get parameters */
	if (ioctl(vconf -> fd, VIDIOCGPICT, &vconf -> vidpic, sizeof(vconf -> vidpic)) == -1)
		error_exit("ioctl(VIDIOCGPICT)");

	/* get capabilities */
	if (ioctl(vconf -> fd, VIDIOCGCAP, &vconf -> vidcap, sizeof(vconf -> vidcap)) == -1)
		error_exit("ioctl(VIDIOCGCAP)");

	/* set capture window */
	if (ioctl(vconf -> fd, VIDIOCGWIN, &vconf -> vidwin, sizeof(vconf -> vidwin)) == -1)
		error_exit("ioctl(VIDIOCGWIN)");

	vconf -> vidwin.x =
		vconf -> vidwin.y = 0;

	if (res == RES_LOW)
	{
		vconf -> vidwin.width = vconf -> vidcap.minwidth;
		vconf -> vidwin.height = vconf -> vidcap.minheight;
	}
	else if (res == RES_HIGH)
	{
		vconf -> vidwin.width = vconf -> vidcap.maxwidth;
		vconf -> vidwin.height = vconf -> vidcap.maxheight;
	}

	if (ioctl(vconf -> fd, VIDIOCSWIN, &vconf -> vidwin, sizeof(vconf -> vidwin)) == -1)
		error_exit("ioctl(VIDIOCSWIN)");

	/* map to memory */
	if (ioctl(vconf -> fd, VIDIOCGMBUF, &vconf -> vidmbuf, sizeof(vconf -> vidmbuf)) == -1)
		error_exit("ioctl(VIDIOCGMBUF)");

	vconf -> img = (unsigned char *)mmap(NULL, vconf -> vidmbuf.size, PROT_READ, MAP_SHARED, vconf -> fd, 0);
	if (!vconf -> img)
		error_exit("mmap");

	/* set device */
	vconf -> vidmmap.frame = 0;
	vconf -> vidmmap.width = vconf -> vidwin.width;
	vconf -> vidmmap.height = vconf -> vidwin.height;
	vconf -> vidmmap.format = vconf -> vidpic.palette;

	return 0;
}

void close_device(vconfig *vconf)
{
	munmap(vconf -> img, vconf -> vidmbuf.size);

	close(vconf -> fd);
}

unsigned char * take_picture(vconfig *vconf)
{
	unsigned char *pic;

	/* start capture */
	if (ioctl(vconf -> fd, VIDIOCMCAPTURE, &vconf -> vidmmap, sizeof(vconf -> vidmmap)) == -1)
		error_exit("ioctl(VIDIOCMCAPTURE)");

	/* synchronize frame */
	if (ioctl(vconf -> fd, VIDIOCSYNC, &vconf -> vidmmap.frame, sizeof(vconf -> vidmmap.frame)) == -1)
		error_exit("ioctl(VIDIOCSYNC)");

	/* return pointer to current frame */
	pic = (unsigned char *)&vconf -> img[vconf -> vidmbuf.offsets[vconf -> vidmmap.frame]];

	/* next time; next frame! */
	vconf -> vidmmap.frame++;
	if (vconf -> vidmmap.frame >= vconf -> vidmbuf.frames)
		vconf -> vidmmap.frame = 0;

	return pic;
}

void help(void)
{
	printf("-d x   device to use\n");
	printf("-o file   file to write entropy data to (mututal exclusive with -d)\n");
	printf("-f x   skip x frames before processing images (in case the device\n");
	printf("       needs a few frames to settle)\n");
	printf("-H     use highest resolution instead of the default lowest res.\n");
	printf("-n     do not fork\n");
}

int main(int argc, char *argv[])
{
	int device_settle = 25;
	vconfig vconf;
	int c;
	char *host = NULL;
	int port = 55225;
	unsigned char *img1, *img2, *unbiased;
	int imginbytes, nunbiased = 0;
	char do_not_fork = 0, log_console = 0, log_syslog = 0;
	char *log_logfile = NULL;
	char *device = NULL;
	unsigned char byte;
	int nbits = 0;
	int socket_fd = -1;
	char *bytes_file = NULL;
	int res = RES_LOW;
	int loop;

	fprintf(stderr, "%s, (C) 2009 by folkert@vanheusden.com\n", server_type);

	while((c = getopt(argc, argv, "Hf:o:i:d:l:sn")) != -1)
	{
		switch(c)
		{
			case 'H':
				res = RES_HIGH;
				break;

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
	if (open_device(&vconf, device, res) == -1)
		error_exit("failure opening %s", device);

	imginbytes = vconf.vidmbuf.size / vconf.vidmbuf.frames;
	dolog(LOG_DEBUG, "img size in bytes %d", imginbytes);

	/* let device settle */
	dolog(LOG_DEBUG, "waiting for device to settle");
	for(loop=0; loop<device_settle; loop++)
		(void)take_picture(&vconf);

	for(;;)
	{
		unsigned char *cur_img;

		if (!bytes_file)
		{
			if (reconnect_server_socket(host, port, &socket_fd, server_type) == -1)
				continue;
		}

		img1 = (unsigned char *)malloc(imginbytes);
		img2 = (unsigned char *)malloc(imginbytes);
		unbiased = (unsigned char *)malloc(imginbytes);
		if (!img1 || !img2 || !unbiased)
			error_exit("out of memory");

		/* take pictures */
		dolog(LOG_DEBUG, "Smile!");
		cur_img = take_picture(&vconf);
		memcpy(img1, cur_img, imginbytes);
		cur_img = take_picture(&vconf);
		memcpy(img2, cur_img, imginbytes);

		/* unbiase */
		dolog(LOG_DEBUG, "Filtering...");
		nunbiased=0;
		for(loop=0; loop<imginbytes; loop+=2)
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
	close_device(&vconf);

	return 0;
}
