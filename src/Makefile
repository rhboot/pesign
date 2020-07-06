SRCDIR = $(realpath .)
TOPDIR = $(realpath ..)

include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults

BINTARGETS=authvar client efikeygen efisiglist pesigcheck pesign pesign-rpmbuild-helper
SVCTARGETS=pesign.sysvinit pesign.service
TARGETS=$(BINTARGETS) $(SVCTARGETS)

all : deps $(TARGETS)

COMMON_SOURCES = cms_common.c content_info.c oid.c password.c \
	signed_data.c signer_info.c ucs2.c
COMMON_PE_SOURCES = wincert.c cms_pe_common.c
AUTHVAR_SOURCES = authvar.c authvar_context.c
CLIENT_SOURCES = pesign_context.c actions.c client.c
EFIKEYGEN_SOURCES = efikeygen.c
EFISIGLIST_SOURCES = efisiglist.c siglist.c
PESIGCHECK_SOURCES = pesigcheck.c pesigcheck_context.c certdb.c
PESIGN_SOURCES = pesign.c pesign_context.c actions.c daemon.c \
		 file_pe.c file_kmod.c pesign_kmod.c

ALL_SOURCES=$(COMMON_SOURCES) $(AUTHVAR_SORUCES) $(CLIENT_SOURCES) \
	$(EFIKEYGEN_SOURCES) $(EFISIGLIST_SOURCES) $(PESIGCHECK_SOURCES) \
	$(PESIGN_SOURCES)
-include $(call deps-of,$(ALL_SOURCES))

authvar : $(call objects-of,$(AUTHVAR_SOURCES) $(COMMON_SOURCES))
# authvar : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
authvar : PKGS=efivar nss nspr popt

client : $(call objects-of,$(CLIENT_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
client : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
client : PKGS=efivar nss nspr popt

efikeygen : $(call objects-of,$(EFIKEYGEN_SOURCES) $(COMMON_SOURCES))
efikeygen : PKGS=efivar nss nspr popt uuid

efisiglist : $(call objects-of,$(EFISIGLIST_SOURCES) $(COMMON_SOURCES))
efisiglist : PKGS=efivar nss nspr popt

pesigcheck : $(call objects-of,$(PESIGCHECK_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
pesigcheck : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
pesigcheck : PKGS=efivar nss nspr popt

pesign : $(call objects-of,$(PESIGN_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
pesign : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
pesign : PKGS=efivar nss nspr popt

pesign-rpmbuild-helper: pesign-rpmbuild-helper.in
	sed \
		-e "s/@@EFI_ARCHES@@/$(EFI_ARCHES)/g" \
		$^ > $@

deps : PKGS=efivar nss nspr popt uuid
deps : $(ALL_SOURCES)
	$(MAKE) -f $(TOPDIR)/Make.deps \
		SOURCES="$(ALL_SOURCES)" \
		PKGS="$(PKGS)" \
		deps

clean :
	@rm -rfv *.o *.a *.so $(TARGETS)
	@rm -rfv .*.d

install_systemd: pesign.service
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(libdatadir)tmpfiles.d/
	$(INSTALL) -m 644 tmpfiles.conf $(INSTALLROOT)$(libdatadir)tmpfiles.d/pesign.conf
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(libdatadir)systemd/system/
	$(INSTALL) -m 644 pesign.service $(INSTALLROOT)$(libdatadir)systemd/system/

install_sysvinit: pesign.sysvinit
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/rc.d/init.d/
	$(INSTALL) -m 755 pesign.sysvinit $(INSTALLROOT)/etc/rc.d/init.d/pesign

install :
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pki/pesign/
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pki/pesign-rh-test/
	$(INSTALL) -d -m 770 $(INSTALLROOT)/var/run/pesign/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 authvar $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 client $(INSTALLROOT)$(bindir)pesign-client
	$(INSTALL) -m 755 efikeygen $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 efisiglist $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 pesigcheck $(INSTALLROOT)$(bindir)
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 pesign.1 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 pesign-client.1 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 efikeygen.1 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 pesigcheck.1 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 authvar.1 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 efisiglist.1 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -m 644 macros.pesign $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(libexecdir)/pesign/
	$(INSTALL) -m 750 pesign-authorize $(INSTALLROOT)$(libexecdir)/pesign/
	$(INSTALL) -m 755 pesign-rpmbuild-helper $(INSTALLROOT)$(libexecdir)/pesign/
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pesign
	$(INSTALL) -m 600 pesign-users $(INSTALLROOT)/etc/pesign/users
	$(INSTALL) -m 600 pesign-groups $(INSTALLROOT)/etc/pesign/groups

.PHONY: all deps clean install
