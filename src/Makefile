SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

LIBS = popt
STATIC_LIBS = $(TOPDIR)/libdpe/libdpe.a
PKLIBS = nss
LDFLAGS =
CCLDFLAGS = -L../libdpe $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags --libs $(pklib)))
CFLAGS += -I../include/ $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib))) -Werror

TARGETS = pesign peverify authvar

all : $(TARGETS)

generic.a : cms_common.o wincert.o password.o ucs2.o oid.o \
	signed_data.o signer_info.o content_info.o

authvar_SOURCES = authvar.c authvar_context.c
authvar_OBJECTS = $(foreach source,$(authvar_SOURCES),$(patsubst %.c,%,$(source)).o) generic.a
authvar : $(authvar_OBJECTS) $(STATIC_LIBS)

pesign_SOURCES = pesign.c pesign_context.c actions.c
pesign_OBJECTS = $(foreach source,$(pesign_SOURCES),$(patsubst %.c,%,$(source)).o) generic.a
pesign : $(pesign_OBJECTS) $(STATIC_LIBS)

peverify_SOURCES = peverify.c peverify_context.c
peverify_OBJECTS = $(foreach source,$(peverify_SOURCES),$(patsubst %.c,%,$(source)).o) generic.a
peverify : $(peverify_OBJECTS) $(STATIC_LIBS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pki/pesign/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 peverify $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 peverify.popt $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/usr/share/man/man1/
	$(INSTALL) -m 644 pesign.1 $(INSTALLROOT)/usr/share/man/man1/
	$(INSTALL) -m 644 peverify.1 $(INSTALLROOT)/usr/share/man/man1/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -m 644 macros.pesign $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -m 644 macros.peverify $(INSTALLROOT)/etc/rpm/

.PHONY: all clean install

include $(TOPDIR)/Make.rules
