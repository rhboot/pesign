SRCDIR = .
TOPDIR = $(SRCDIR)/..

include $(TOPDIR)/Make.defaults

FORMAT=efi-app-$(HOSTARCH)
LDFLAGS = -nostdlib -T $(LIBDIR)/gnuefi/elf_$(HOSTARCH)_efi.lds -shared -Bsymbolic $(LIBDIR)/gnuefi/crt0-efi-$(HOSTARCH).o -L$(LIBDIR)
LIBS=-lefi -lgnuefi $(shell $(CC) -print-libgcc-file-name)
CCLDFLAGS =
BUILDFLAGS = -I/usr/include/efi/ -I/usr/include/efi/$(HOSTARCH)/ -I/usr/include/efi/protocol -fpic -fshort-wchar -fno-reorder-functions -fno-strict-aliasing -fno-merge-constants -mno-red-zone -Wimplicit-function-declaration

TARGETS = setupsb.efi dumpsb.efi clearpk.efi

all : $(TARGETS)

clean : 
	@rm -rfv *.o *.a *.so $(TARGETS)

install :
	$(INSTALL) -d -m 755 $(INSTALLROOT)/boot/efi/EFI/redhat/
	$(INSTALL) -m 755 *.efi $(INSTALLROOT)/boot/efi/EFI/redhat/

.PHONY: all clean install

include $(TOPDIR)/Make.efirules
