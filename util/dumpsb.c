#include <efi.h>
#include <efilib.h>

#include "shelliface.h"
#include "sb.h"

static void
dumphex(UINT8 *data, UINTN data_size)
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

static void
dumpvar(EFI_SYSTEM_TABLE *systab, EFI_GUID *guid, CHAR16 *name)
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
show_signature_support(EFI_SYSTEM_TABLE *systab, UINTN showguid)
{
	EFI_STATUS rc = EFI_SUCCESS;
	char *data = NULL;
	UINTN data_size = 0;
	UINTN found = 0;
	EFI_GUID *guid;
	int i, j;

	struct {
		EFI_GUID *guid;
		CHAR16 *name;
		int required;
	} hashes[] = {
		{ &gEfiCertSha1Guid, L"SHA-1", 1 },
		{ &gEfiCertSha256Guid, L"SHA-256", 0 },
		{ &gEfiCertRsa2048Guid, L"RSA-2048", 0 },
		{ &gEfiCertRsa2048Sha1Guid, L"RSA-2048 + SHA-1", 0 },
		{ &gEfiCertRsa2048Sha256Guid, L"RSA-2048 + SHA-256", 0 },
		{ &gEfiCertX509Guid, L"X509", 1 },
		{ &gEfiCertPkcs7Guid, L"PKCS-7", 0 },
		{ NULL, L"" }
	};

	data = LibGetVariableAndSize(L"SignatureSupport", &EfiGlobalVariable,
				&data_size);
	guid = (EFI_GUID *)data;
	Print(L"Supported hashes:\n");
	for (i = 0; i < data_size / sizeof(*guid); i++, guid++) {
		found = 0;
		for (j = 0; hashes[j].guid != NULL; j++) {
			if (!CompareMem(hashes[j].guid, guid, sizeof(*guid))) {
 				if (showguid)
					Print(L"        %s (%g)\n", hashes[j].name, guid);
				else
					Print(L"        %s\n", hashes[j].name);
				hashes[j].required = 0;
				found = 1;
				continue;
			}
		}
		if (!found) {
			Print(L"        Unknown hash (%g)\n", guid);
		}
	}

	for (j = 0; hashes[j].guid != NULL; j++) {
		if (hashes[j].required) {
			Print(L"ERROR: Did not find required hash \"%s\"\n",
				hashes[j].name);
			rc = EFI_NOT_FOUND;
		}
	}

	FreePool(data);
	return rc;
}


static EFI_STATUS
get_args(EFI_HANDLE image, UINTN *argc, CHAR16 ***argv)
{
	EFI_STATUS rc;
	EFI_SHELL_INTERFACE *shell;
	EFI_GUID gEfiShellInterfaceGuid = EFI_SHELL_INTERFACE_GUID;

	rc = uefi_call_wrapper(BS->OpenProtocol, 6,
				image,
				&gEfiShellInterfaceGuid,
				(VOID **)&shell, image, NULL,
				EFI_OPEN_PROTOCOL_GET_PROTOCOL);

	if (EFI_ERROR(rc))
		return rc;

	*argc = shell->Argc;
	*argv = shell->Argv;
	uefi_call_wrapper(BS->CloseProtocol, 4, image,
			&gEfiShellInterfaceGuid,
			image, NULL);
	return EFI_SUCCESS;
}


static void
usage(void)
{
	Print(L"Usage: dumpsb [ -s | --showguid ]\n");
}



EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
        UINTN argc;
        CHAR16 **argv;
	EFI_STATUS rc = EFI_SUCCESS;
	int i;
	UINTN showguid = 0;

	InitializeLib(image, systab);

        rc = get_args(image, &argc, &argv);
	if (EFI_ERROR(rc)) {
		Print(L"ERROR: Parsing command line arguments: %d\n", rc);
		return rc;
	}

        if (argc == 2) {
		if (!StrCmp(argv[1], L"help") ||
			!StrCmp(argv[1], L"/help") ||
			!StrCmp(argv[1], L"--help") ||
			!StrCmp(argv[1], L"-?")) {
				usage();
				return EFI_SUCCESS;
		} else if (!StrCmp(argv[1], L"/showguid") ||
			!StrCmp(argv[1], L"--showguid") ||
			!StrCmp(argv[1], L"-s")) {
				showguid = 1;
		} else {
			usage();
			return EFI_INVALID_PARAMETER;
		}
        }

	rc = show_signature_support(systab, showguid);
	dumpvar(systab, &EfiGlobalVariable, L"SetupMode");
	dumpvar(systab, &EfiGlobalVariable, L"SecureBoot");
	dumpvar(systab, &EfiGlobalVariable, EFI_PLATFORM_KEY_NAME);
	dumpvar(systab, &EfiGlobalVariable, EFI_KEY_EXCHANGE_KEY_NAME);
	dumpvar(systab, &gEfiImageSecurityDatabaseGuid,	EFI_IMAGE_SECURITY_DATABASE);
	dumpvar(systab, &gEfiImageSecurityDatabaseGuid,	EFI_IMAGE_SECURITY_DATABASE1);

	return rc;
}
