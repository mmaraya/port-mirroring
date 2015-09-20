sbin_PROGRAMS = port-mirroring
port_mirroring_SOURCES = port-mirroring.c
port_mirroring_CFLAGS = -D_ENABLE_THREADS
EXTRA_DIST = port-mirroring.conf port-mirroringd
install-data-local:
	$(INSTALL_DATA) $(srcdir)/port-mirroring.conf $(sysconfdir)/port-mirroring
	$(INSTALL_SCRIPT) $(srcdir)/port-mirroringd $(sysconfdir)/init.d/port-mirroring
