SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

LIBS = popt dpe
PKLIBS = nss
LDFLAGS =
CCLDFLAGS = -L../libdpe $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags --libs $(pklib)))
CFLAGS += -I../include/ $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib)))

TARGETS = pesign

all : $(TARGETS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/usr/bin/
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(PREFIX)/usr/bin/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)$(PREFIX)/etc/popt.d/

pesign : pesign.o io.o

.PHONY: all clean install

include $(TOPDIR)/Make.rules
