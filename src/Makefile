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
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pki/pesign/

pesign : pesign.o cert.o io.o

.PHONY: all clean install

include $(TOPDIR)/Make.rules
