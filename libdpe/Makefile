SRCDIR = .
TOPDIR = $(SRCDIR)/..

SONAME = libdpe.so.0

include $(TOPDIR)/Make.defaults

TARGETS = libdpe.so libdpe.a
all : $(TARGETS)

SOURCES = $(patsubst %.c,%,$(wildcard *.c))
OBJECTS = $(foreach source,$(SOURCES),$(source).o)
DEPS = $(foreach source,$(SOURCES),.$(source).P)
# PEOBJECTS = $(foreach source,$(SOURCES),$(source)_pe.o)

libdpe.a :: $(OBJECTS)

libdpe.so :: $(OBJECTS)

deps : $(DEPS)

-include $(DEPS)

depclean :
	@rm -fv .*.P

clean : depclean
	@rm -rfv *~ *.o *.a *.so

install :
	echo "LIBDIR: $(LIBDIR)"
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(LIBDIR)
	for x in $(TARGETS) ; do \
		$(INSTALL) -m 755  $$x $(INSTALLROOT)$(LIBDIR) ; \
	done

.PHONY: all clean install

include $(TOPDIR)/Make.rules
