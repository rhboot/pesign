SRCDIR = .
TOPDIR = $(SRCDIR)/..

SONAME = libdpe.so.0

include $(TOPDIR)/Make.defaults

all : libdpe.so libdpe.a

SOURCES = libdpe pe_error pe_begin

libdpe.a : $(foreach source,$(SOURCES),$(source)_pe.o)
	$(AR) -cvq $@ $^

libdpe.so :: $(foreach source,$(SOURCES),$(source).o)

clean : 
	@rm -rfv *~ *.o *.a *.so

install :

.PHONY: all clean install

include $(TOPDIR)/Make.rules
