SRCDIR = .
TOPDIR = $(SRCDIR)/..

SONAME = libdpe.so.0

include $(TOPDIR)/Make.defaults

all : libdpe.so libdpe.a

libdpe.a : libdpe_pe.o pe_error_pe.o pe_begin_pe.o
	$(AR) -cvq $@ $^

libdpe.so :: pe_error.o pe_begin.o

clean : 
	@rm -rfv *~ *.o *.a *.so

install :

.PHONY: all clean install

include $(TOPDIR)/Make.rules
