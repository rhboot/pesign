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

generic_SOURCES = cms_common.c wincert.c password.c ucs2.c oid.c signed_data.c signer_info.c content_info.c
generic_OBJECTS = $(foreach source,$(generic_SOURCES),$(patsubst %.c,%,$(source)).o)
generic_DEPS = $(foreach source,$(generic_SOURCES),.$(patsubst %.c,%,$(source)).P)
generic.a : $(generic_OBJECTS)

authvar_SOURCES = authvar.c authvar_context.c
authvar_OBJECTS = $(foreach source,$(authvar_SOURCES),$(patsubst %.c,%,$(source)).o) generic.a
authvar_DEPS = $(foreach source,$(authvar_SOURCES),.$(patsubst %.c,%,$(source)).P)
authvar : $(authvar_OBJECTS) $(STATIC_LIBS)

pesign_SOURCES = pesign.c pesign_context.c actions.c
pesign_OBJECTS = $(foreach source,$(pesign_SOURCES),$(patsubst %.c,%,$(source)).o) generic.a
pesign_DEPS = $(foreach source,$(pesign_SOURCES),.$(patsubst %.c,%,$(source)).P)
pesign : $(pesign_OBJECTS) $(STATIC_LIBS)

peverify_SOURCES = peverify.c peverify_context.c certdb.c
peverify_OBJECTS = $(foreach source,$(peverify_SOURCES),$(patsubst %.c,%,$(source)).o) generic.a
peverify_DEPS = $(foreach source,$(peverify_SOURCES),.$(patsubst %.c,%,$(source)).P)
peverify : $(peverify_OBJECTS) $(STATIC_LIBS)

deps : $(generic_DEPS)$(authvar_DEPS) $(pesign_DEPS) $(peverify_DEPS)

depclean :
	@rm -fv .*.P

-include $(generic_DEPS) $(authvar_DEPS) $(pesign_DEPS) $(peverify_DEPS)

clean : depclean
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pki/pesign/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -m 755 peverify $(INSTALLROOT)$(PREFIX)/bin/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/usr/share/man/man1/
	$(INSTALL) -m 644 pesign.1 $(INSTALLROOT)/usr/share/man/man1/
	$(INSTALL) -m 644 peverify.1 $(INSTALLROOT)/usr/share/man/man1/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -m 644 macros.pesign $(INSTALLROOT)/etc/rpm/

.PHONY: all deps clean install

include $(TOPDIR)/Make.rules
