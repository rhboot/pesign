TOPDIR = $(shell echo $$PWD)

include $(TOPDIR)/Make.defaults

SUBDIRS := include libdpe src util
DOCDIR := /share/doc/
VERSION = 0.1

all : $(SUBDIRS)

$(SUBDIRS) :
	$(MAKE) -C $@ TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH)

clean :
	@for x in $(SUBDIRS) ; do make -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH) $@ ; done

install :
	@for x in $(SUBDIRS) ; do make -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH) $@ ; done
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(PREFIX)$(DOCDIR)/pesign/
	$(INSTALL) -m 644 COPYING $(INSTALLROOT)$(PREFIX)$(DOCDIR)/pesign/

.PHONY: $(SUBDIRS) clean install

include $(TOPDIR)/Make.rules
