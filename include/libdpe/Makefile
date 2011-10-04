SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

SUBDIRS = libdpe

all:

clean:

install:
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/include/libdpe/
	$(INSTALL) -m 644 *.h $(INSTALLROOT)$(PREFIX)/include/libdpe/

include $(TOPDIR)/Make.rules
