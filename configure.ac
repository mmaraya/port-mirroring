#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.67])
AC_INIT([port-mirroring], [1.3], [gengw2000@163.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PREFIX_DEFAULT()

#libtool macros
#AC_DISABLE_SHARED
#AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pcap],[pcap_open_live])
AC_CHECK_LIB([pthread], [pthread_mutex_lock])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netinet/in.h stdlib.h string.h sys/socket.h syslog.h unistd.h pcap.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_CHECK_FUNCS([memset socket strchr strstr])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
