#define _LARGEFILE64_SOURCE     /* required for GLIBC to enable stat64 and friends */
/* I read somewhere that this is needed on HP-UX */
#define _INCLUDE_HPUX_SOURCE
#define _INCLUDE_POSIX_SOURCE
#define _INCLUDE_XOPEN_SOURCE
#define _INCLUDE_XOPEN_SOURCE_EXTENDED
#define _INCLUDE_AES_SOURCE

#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <regex.h>

#include <sys/stat.h>
#include <fcntl.h>

#include <netinet/in.h>

#include <sys/ioctl.h>

#ifdef __APPLE__
#include <util.h>
#endif
#ifdef __OpenBSD__
#include <util.h>
#endif
#if defined(linux) || defined(__CYGWIN__) || defined(__GNU__) || defined(__GLIBC__)
#include <pty.h>
#endif
#ifdef __FreeBSD__
#include <libutil.h>
#endif
#if defined(sun) || defined(__sun)
#include <sys/stropts.h>
#include <stdlib.h>
#endif
#if defined(IRIX) || defined(IRIX64)
#endif
#if defined(AIX)
#endif
#if defined(_HPUX_SOURCE)
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/termios.h>
#include <sys/bsdtty.h>
#include <sys/ttold.h>
#include <sys/ptyio.h>
#include <sys/strtio.h>
#include <sys/eucioctl.h>
#endif
#include <sys/socket.h>


/* the following code was mostly taken from: */

/*      $NetBSD: sshpty.c,v 1.8 2002/10/15 15:33:04 manu Exp $  */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Allocating a pseudo-terminal, and making it the controlling tty.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

/* additional code for *BSD/Linux/Apple, AIX and IRIX by folkert@vanheusden.com */

int get_pty_and_fork(int *fd_master, int *fd_slave)
{
#if defined(__FreeBSD__) || defined(linux) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__) || defined(__CYGWIN__) || defined(__GNU__) || defined(__GLIBC__)

	if (openpty(fd_master, fd_slave, NULL, NULL, NULL) == -1)
		return -1;

	return fork();

#elif defined(sun) || defined(__sun) || defined(AIX) || defined(_HPUX_SOURCE) || defined(OSF1) || defined(scoos)

	/*
	 * This code is used e.g. on Solaris 2.x.  (Note that Solaris 2.3
	 * also has bsd-style ptys, but they simply do not work.)
	 */
	int ptm;
	char *pts;
	pid_t pid;
#if defined(AIX)
	char *multiplexer = "/dev/ptc";
#else
	char *multiplexer = "/dev/ptmx";
#endif

	ptm = open(multiplexer, O_RDWR | O_NOCTTY);
	if (ptm < 0) {
		return -1;
	}
	*fd_master = ptm;

	pid = fork();
	if (pid == 0)
	{
		if (grantpt(ptm) < 0) exit(1);
		if (unlockpt(ptm) < 0) exit(1);
		setsid(); /* lose old controlling terminal (FvH) */
		pts = ptsname(ptm);
		if (pts == NULL) exit(1);

		/* Open the slave side. */
		*fd_slave = open(pts, O_RDWR | O_NOCTTY);
		if (*fd_slave < 0) exit(1);

#if !defined(AIX) && !defined(scoos)
		/* Push the appropriate streams modules, as described in Solaris pts(7). */
		if (ioctl(*fd_slave, I_PUSH, "ptem") < 0) exit(1);
		if (ioctl(*fd_slave, I_PUSH, "ldterm") < 0) exit(1);
		(void)ioctl(*fd_slave, I_PUSH, "ttcompat"); /* not on HP-UX? */
#endif
	}

	return pid;

#elif defined(IRIX) || defined(IRIX64)

	char *line = _getpty(fd_master, O_RDWR | O_NDELAY, 0600, 0);
	if (line == NULL) exit(1);

	*fd_slave = open(line, O_RDWR);
	if (*fd_slave < 0) exit(1);

	return fork();

#else

#error I'm sorry, but I don't know what kind of system this is.

#endif
}
