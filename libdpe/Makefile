SRCDIR = .
TOPDIR = $(SRCDIR)/..

SONAME = libdpe.so.0

include $(TOPDIR)/Make.defaults

# TARGETS = libdpe.so libdpe.a
TARGETS = libdpe.so
all : $(TARGETS)

SOURCES = $(patsubst %.c,%,$(wildcard *.c))
OBJECTS = $(foreach source,$(SOURCES),$(source).o)
PEOBJECTS = $(foreach source,$(SOURCES),$(source)_pe.o)

libdpe.a :: $(PEOBJECTS)

libdpe.so :: $(OBJECTS)

clean : 
	@rm -rfv *~ *.o *.a *.so

install :
	echo "LIBDIR: $(LIBDIR)"
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(LIBDIR)
	for x in $(TARGETS) ; do \
		$(INSTALL) -m 755  $$x $(INSTALLROOT)$(LIBDIR) ; \
	done

.PHONY: all clean install

include $(TOPDIR)/Make.rules
