SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

LIBS = popt
LDFLAGS=
CCLDFLAGS=

TARGETS = pesign

all : $(TARGETS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :

pesign : pesign.o

.PHONY: all clean install

include $(TOPDIR)/Make.rules
