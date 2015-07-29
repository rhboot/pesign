SRCDIR = $(realpath .)
TOPDIR = $(realpath ..)

include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults

SUBDIRS = libdpe

clean all install :
	for x in $(SUBDIRS) ; do \
		$(MAKE) -C $$x $@ ; \
	done

$(SUBDIRS) :
	$(MAKE) -C $@ all

.PHONY: $(SUBDIRS)
