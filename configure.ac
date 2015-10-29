#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([port-mirroring], [1.4], [mmaraya@users.noreply.github.com])
AC_PREFIX_DEFAULT()
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_CC
AC_CHECK_PROG([CPPCHECK], [cppcheck], [yes], [no])
AM_CONDITIONAL([HAVE_CPPCHECK], [test "x$CPPCHECK" = xyes])

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
