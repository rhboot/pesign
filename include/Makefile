SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

SUBDIRS = libdpe

all : $(SUBDIRS)

$(SUBDIRS) :
	$(MAKE) -C $@ TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH)

clean :
	@for x in $(SUBDIRS) ; do $(MAKE) -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH) $@ ; done

install :
	@for x in $(SUBDIRS) ; do $(MAKE) -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH) $@ ; done

.PHONY: all $(SUBDIRS) clean install

include $(TOPDIR)/Make.rules
