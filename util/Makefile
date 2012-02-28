SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

FORMAT=efi-app-x86_64
LDFLAGS = -nostdlib -T /usr/lib64/gnuefi/elf_x86_64_efi.lds -shared -Bsymbolic /usr/lib64/gnuefi/crt0-efi-x86_64.o -L/usr/lib64/
LIBS=-lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name)
CCLDFLAGS =
CFLAGS = -I/usr/include/efi/ -I/usr/include/efi/x86_64/ -I/usr/include/efi/protocol -fpic -fshort-wchar -fno-reorder-functions -fno-strict-aliasing -fno-merge-constants -mno-red-zone 

TARGETS = dumpsb.efi setpk.efi clearpk.efi

all : $(TARGETS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)/boot/efi/EFI/redhat/
	$(INSTALL) -m 755 *.efi $(INSTALLROOT)$(PREFIX)/boot/efi/EFI/redhat/

setpk.o : setpk.c cert.h
setpk.so : $(OBJECTS)

.PHONY: all clean install

include $(TOPDIR)/Make.efirules
