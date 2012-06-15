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

GITTAG = $(VERSION)-1

test-archive:
	@rm -rf /tmp/pesign-$(VERSION) /tmp/pesign-$(VERSION)-tmp
	@mkdir -p /tmp/pesign-$(VERSION)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/pesign-$(VERSION)-tmp/ ; tar x )
	@git diff | ( cd /tmp/pesign-$(VERSION)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/pesign-$(VERSION)-tmp/ /tmp/pesign-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/pesign-$(VERSION).tar.bz2 pesign-$(VERSION)
	@rm -rf /tmp/pesign-$(VERSION)
	@echo "The archive is in pesign-$(VERSION).tar.bz2"

archive:
	git tag $(GITTAG) refs/heads/master
	@rm -rf /tmp/pesign-$(VERSION) /tmp/pesign-$(VERSION)-tmp
	@mkdir -p /tmp/pesign-$(VERSION)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/pesign-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/pesign-$(VERSION)-tmp/ /tmp/pesign-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/pesign-$(VERSION).tar.bz2 pesign-$(VERSION)
	@rm -rf /tmp/pesign-$(VERSION)
	@echo "The archive is in pesign-$(VERSION).tar.bz2"


