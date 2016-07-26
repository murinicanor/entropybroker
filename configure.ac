AC_INIT([entropy_broker], [2.8])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([foreign])

#INTI_REQUIRED_VERSION=1.0.7
#PKG_CHECK_MODULES(INTI, inti-1.0 >= $INTI_REQUIRED_VERSION)
#AC_SUBST(INTI_CFLAGS)
#AC_SUBST(INTI_LIBS)

AC_PROG_CC
AC_PROG_CXX
AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT

PKG_CHECK_MODULES([cryptopp], [libcrypto++], [AC_MSG_FAILURE([cryptopp development files not found!])])
