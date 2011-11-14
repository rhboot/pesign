SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

LIBS = popt dpe
PKLIBS = nss
LDFLAGS =
CCLDFLAGS = -L../libdpe $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags --libs $(pklib)))
CFLAGS += -I../include/ $(foreach pklib,$(PKLIBS), $(shell pkg-config --cflags $(pklib)))

TARGETS = pesign

all : $(TARGETS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :

pesign : pesign.o io.o

.PHONY: all clean install

include $(TOPDIR)/Make.rules
