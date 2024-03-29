SRCDIR = $(realpath .)
TOPDIR = $(realpath ..)

include $(TOPDIR)/Make.version
include $(TOPDIR)/Make.rules
include $(TOPDIR)/Make.defaults

BINTARGETS=authvar client efikeygen pesigcheck pesign \
	   pesign-rpmbuild-helper pesum
CFGTARGETS=tmpfiles.conf
SVCTARGETS=pesign.sysvinit pesign.service
MAN1TARGETS=authvar.1 efikeygen.1 pesigcheck.1 pesign-client.1 pesign.1

TARGETS=$(BINTARGETS) $(SVCTARGETS) $(CFGTARGETS)
ifeq ($(ENABLE_DOCS), 1)
TARGETS += $(MAN1TARGETS)
endif

all : deps $(TARGETS)

COMMON_SOURCES = cms_common.c content_info.c \
		 errno-guard.c \
		 oid.c \
		 password.c \
		 signed_data.c signer_info.c \
		 text.c \
		 ucs2.c util.c
COMMON_PE_SOURCES = wincert.c cms_pe_common.c
AUTHVAR_SOURCES = authvar.c authvar_context.c
CLIENT_SOURCES = pesign_context.c actions.c client.c
EFIKEYGEN_SOURCES = efikeygen.c
PESIGCHECK_SOURCES = pesigcheck.c pesigcheck_context.c certdb.c
PESIGN_SOURCES = pesign.c pesign_context.c actions.c daemon.c \
		 file_pe.c file_kmod.c pesign_kmod.c
PESUM_SOURCES = pesum.c pesign_context.c actions.c \
		file_pe.c file_kmod.c pesign_kmod.c

ALL_SOURCES=$(COMMON_SOURCES) $(AUTHVAR_SORUCES) $(CLIENT_SOURCES) \
	$(EFIKEYGEN_SOURCES) $(PESIGCHECK_SOURCES) $(PESIGN_SOURCES) \
	$(PESUM_SOURCES)
-include $(call deps-of,$(ALL_SOURCES))

authvar : $(call objects-of,$(AUTHVAR_SOURCES) $(COMMON_SOURCES))
# authvar : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
authvar : PKGS=efivar nss nspr popt

client : $(call objects-of,$(CLIENT_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
client : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
client : PKGS=efivar nss nspr popt

efikeygen : $(call objects-of,$(EFIKEYGEN_SOURCES) $(COMMON_SOURCES))
efikeygen : PKGS=efivar nss nspr popt uuid

pesigcheck : $(call objects-of,$(PESIGCHECK_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
pesigcheck : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
pesigcheck : PKGS=efivar nss nspr popt

pesign : $(call objects-of,$(PESIGN_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
pesign : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
pesign : PKGS=efivar nss nspr popt

pesum : $(call objects-of,$(PESUM_SOURCES) $(COMMON_SOURCES) $(COMMON_PE_SOURCES))
pesum : LDLIBS+=$(TOPDIR)/libdpe/libdpe.a
pesum : PKGS=efivar nss nspr popt

deps : PKGS=efivar nss nspr popt uuid
deps : $(ALL_SOURCES)
	$(MAKE) -f $(TOPDIR)/Make.deps \
		SOURCES="$(ALL_SOURCES)" \
		PKGS="$(PKGS)" \
		deps

clean :
	@rm -rfv $(TARGETS)
	@$(call removes)

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
	$(INSTALL) -d -m 770 $(INSTALLROOT)$(rundir)pesign/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 authvar $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 pesign $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 pesum $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 client $(INSTALLROOT)$(bindir)pesign-client
	$(INSTALL) -m 755 efikeygen $(INSTALLROOT)$(bindir)
	$(INSTALL) -m 755 pesigcheck $(INSTALLROOT)$(bindir)
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/popt.d/
	$(INSTALL) -m 644 pesign.popt $(INSTALLROOT)/etc/popt.d/
ifeq ($(ENABLE_DOCS), 1)
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(mandir)man1/
	$(INSTALL) -m 644 $(MAN1TARGETS) $(INSTALLROOT)$(mandir)man1/
endif
	$(INSTALL) -d -m 755 $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -m 644 macros.pesign $(INSTALLROOT)/etc/rpm/
	$(INSTALL) -d -m 755 $(INSTALLROOT)$(libexecdir)/pesign/
	$(INSTALL) -m 755 pesign-rpmbuild-helper $(INSTALLROOT)$(libexecdir)/pesign/
	$(INSTALL) -d -m 700 $(INSTALLROOT)/etc/pesign
	$(INSTALL) -m 600 pesign-users $(INSTALLROOT)/etc/pesign/users
	$(INSTALL) -m 600 pesign-groups $(INSTALLROOT)/etc/pesign/groups

.PHONY: all deps clean install
