SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

LIBS = popt
STATIC_LIBS = $(TOPDIR)/libdpe/libdpe.a
PKLIBS = nss
LDFLAGS =
CCLDFLAGS = -L../libdpe $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags --libs $(pklib)))
CFLAGS += -I../include/ $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib))) -Werror

TARGETS = pesign authvar

all : $(TARGETS)

authvar_SOURCES = $(filter-out $(wildcard pesign*.c), $(wildcard *.c))
authvar_OBJECTS = $(foreach source,$(authvar_SOURCES),$(patsubst %.c,%,$(source)).o)
authvar : $(authvar_OBJECTS) $(STATIC_LIBS)

pesign_SOURCES = $(filter-out $(wildcard authvar*.c), $(wildcard *.c))
pesign_OBJECTS = $(foreach source,$(pesign_SOURCES),$(patsubst %.c,%,$(source)).o)
pesign : $(pesign_OBJECTS) $(STATIC_LIBS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pki/pesign/


.PHONY: all clean install

include $(TOPDIR)/Make.rules
