TOPDIR = $(shell echo $$PWD)

include $(TOPDIR)/Make.defaults

SUBDIRS := include libdpe src

all : $(SUBDIRS)

$(SUBDIRS) :
	$(MAKE) -C $@ TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH)

clean :
	@for x in $(SUBDIRS) ; do make -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH) $@ ; done

install :
	@for x in $(SUBDIRS) ; do make -C $${x} TOPDIR=$(TOPDIR) SRCDIR=$(TOPDIR)/$@/ ARCH=$(ARCH) $@ ; done

.PHONY: $(SUBDIRS) clean install

include $(TOPDIR)/Make.rules
