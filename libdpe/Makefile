SRCDIR = .
TOPDIR = $(SRCDIR)/..

SONAME = libdpe.so.0

include $(TOPDIR)/Make.defaults

all : libdpe.so libdpe.a

libdpe.a : libdpe_pe.o
	$(AR) -cvq $@ $^

clean : 
	@rm -rfv *~ *.o *.a *.so

install :

.PHONY: all clean install

include $(TOPDIR)/Make.rules
