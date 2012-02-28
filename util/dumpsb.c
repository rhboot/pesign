
#include <efi.h>
#include <efilib.h>

#include "sb.h"
#include "cert.h"

EFI_GUID rh_guid = {0xade9e48f, 0x9cb8, 0x98e6, {0x31,0xaf,0xb4,0xe6,0x00,0x9e,0x2f,0xe3}};

static void dumphex(UINT8 *data, UINTN data_size)
{
	int i, j;
	for (i = 0, j = 0; i < data_size; i++, j++) {
		Print(L"%02x ", data[i]);
		if (j == 15) {
			j = -1;
			Print(L"\n");
		}
	}
	if (j != -1)
		Print(L"\n");
}

static void dumpvar(EFI_SYSTEM_TABLE *systab, EFI_GUID *guid, CHAR16 *name)
{
	char *data = NULL;
	UINTN data_size = 0;

	Print(L"Dumping ");
	Print(name);
	Print(L"\n");
	data = LibGetVariableAndSize(name, guid, &data_size);
	dumphex(data, data_size);
	FreePool(data);
}

EFI_STATUS
show_signature_support(EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc = EFI_SUCCESS;
	char *data = NULL;
	UINTN data_size = 0;
	EFI_GUID *guid;
	int i, j;

	struct {
		EFI_GUID *guid;
		CHAR16 *name;
		int required;
	} hashes[] = {
		{ &gEfiCertSha256Guid, L"SHA-256", 0 },
		{ &gEfiCertRsa2048Guid, L"RSA-2048", 0 },
		{ &gEfiCertRsa2048Sha256Guid, L"RSA-2048 + SHA-256", 0 },
		{ &gEfiCertSha1Guid, L"SHA-1", 1 },
		{ &gEfiCertRsa2048Sha1Guid, L"RSA-2048 + SHA-1", 0 },
		{ &gEfiCertX509Guid, L"X509", 1 },
		{ &gEfiCertPkcs7Guid, L"PKCS-7", 0 },
		{ NULL, L"" }
	};

	data = LibGetVariableAndSize(L"SignatureSupport", &EfiGlobalVariable,
				&data_size);
	guid = (EFI_GUID *)data;
	Print(L"Supported hashes: \n");
	for (i = 0; i < data_size / sizeof(*guid); i++, guid++) {
		for (j = 0; hashes[j].guid != NULL; j++) {
			if (!CompareMem(hashes[j].guid, guid, sizeof(*guid))) {
				Print(L"        %s\n", hashes[j].name);
				hashes[j].required = 0;
				continue;
			}
		}
	}

	for (j = 0; hashes[j].guid != NULL; j++) {
		if (hashes[j].required) {
			Print(L"Did not find required hash \"%s\"\n",
				hashes[j].name);
			Print(L"Not continuing.\n");
			rc = EFI_NOT_FOUND;
		}
	}

	FreePool(data);
	return rc;
}

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc = EFI_SUCCESS;
	int i;

	InitializeLib(image, systab);

	rc = show_signature_support(systab);
	dumpvar(systab, &EfiGlobalVariable, L"SetupMode");
	dumpvar(systab, &EfiGlobalVariable, L"SecureBoot");
	dumpvar(systab, &EfiGlobalVariable, EFI_PLATFORM_KEY_NAME);
	dumpvar(systab, &EfiGlobalVariable, EFI_KEY_EXCHANGE_KEY_NAME);
	dumpvar(systab, &gEfiImageSecurityDatabaseGuid,	EFI_IMAGE_SECURITY_DATABASE);
	dumpvar(systab, &gEfiImageSecurityDatabaseGuid,	EFI_IMAGE_SECURITY_DATABASE1);
	return rc;
}

