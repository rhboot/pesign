SRCDIR = $(realpath .)
TOPDIR = $(realpath ..)

include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults

LIBTARGETS=libdpe.so
STATICLIBTARGETS=libdpe.a
TARGETS=$(LIBTARGETS) $(STATICLIBTARGETS)

LIBDPE_SOURCES = $(sort $(wildcard *.c))
ALL_SOURCES=$(LIBDPE_SOURCES)
-include $(call deps-of,$(ALL_SOURCES))

all : deps $(TARGETS)

libdpe.a : $(call objects-of,$(LIBDPE_SOURCES))
libdpe.a : LIBS=pthread
# libdpe.a : | $(wildcard *.h) $(wildcard $(TOPDIR)/include/libdpe/*.h)
libdpe.so : $(call objects-of,$(LIBDPE_SOURCES))
libdpe.so : LIBS=pthread
# libdpe.so : | $(wildcard *.h) $(wildcard $(TOPDIR)/include/libdpe/*.h)

deps : $(ALL_SOURCES)
	$(MAKE) -f $(TOPDIR)/Make.deps deps SOURCES="$(ALL_SOURCES)"

clean :
	@rm -rfv *~ *.o *.a *.so *.so.* .*.d

#install :
#	$(INSTALL) -d -m 755 $(DESTDIR)$(libdir)
#	$(foreach x,$(LIBTARGETS), \
#		$(INSTALL) -m 755 $(x) $(DESTDIR)$(libdir)/$(x).$(VERSION) ;\
#		ln -fs $(x).$(VERSION) $(DESTDIR)$(libdir)/$(x).$(MAJOR_VERSION) ;\
#		ln -fs $(x).$(VERSION) $(DESTDIR)$(libdir)/$(x); )
#	$(foreach x,$(STATICLIBTARGETS), \
#		$(INSTALL) -m 644 $(x) $(DESTDIR)$(libdir)/$(x); )

.SECONDARY : $(foreach x,$(LIBTARGETS),$(x).$(VERSION) $(x).$(MAJOR_VERSION))
