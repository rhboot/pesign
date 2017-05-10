SRCDIR = $(realpath .)
TOPDIR = $(realpath .)

include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults
include $(TOPDIR)/Make.coverity

SUBDIRS := include libdpe src

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(docdir)/pesign-$(VERSION)/
	$(INSTALL) -pm 644 COPYING $(INSTALLROOT)$(docdir)/pesign-$(VERSION)/
	@set -e ; for x in $(SUBDIRS) ; do \
		$(MAKE) -C $$x $@ ; \
	done

install_systemd install_sysvinit : install
	@set -e ; for x in $(SUBDIRS) ; do \
		$(MAKE) -C $$x $@ ; \
	done

distclean : | clean

clean deps all : | Make.version
	@set -e ; for x in $(SUBDIRS) ; do \
		$(MAKE) -C $$x $@ ; \
	done

$(SUBDIRS) :
	$(MAKE) -C $@ all

.PHONY: $(SUBDIRS)

GITTAG = $(VERSION)

test-archive:
	@rm -rf /tmp/pesign-$(VERSION) /tmp/pesign-$(VERSION)-tmp
	@mkdir -p /tmp/pesign-$(VERSION)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/pesign-$(VERSION)-tmp/ ; tar x )
	@git diff | ( cd /tmp/pesign-$(VERSION)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/pesign-$(VERSION)-tmp/ /tmp/pesign-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/pesign-$(VERSION).tar.bz2 pesign-$(VERSION)
	@rm -rf /tmp/pesign-$(VERSION)
	@echo "The archive is in pesign-$(VERSION).tar.bz2"

tag:
	git tag -s $(GITTAG) refs/heads/master

archive: tag
	@rm -rf /tmp/pesign-$(VERSION) /tmp/pesign-$(VERSION)-tmp
	@mkdir -p /tmp/pesign-$(VERSION)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/pesign-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/pesign-$(VERSION)-tmp/ /tmp/pesign-$(VERSION)/
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/pesign-$(VERSION).tar.bz2 pesign-$(VERSION)
	@rm -rf /tmp/pesign-$(VERSION)
	@echo "The archive is in pesign-$(VERSION).tar.bz2"


