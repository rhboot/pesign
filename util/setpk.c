
#include <efi.h>
#include <efilib.h>

#include "sb.h"
#include "cert.h"

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
	UINTN data_size = 16384;

	data = AllocatePool(17384);

	Print(L"Dumping ");
	Print(name);
	Print(L"\n");
	uefi_call_wrapper(systab->RuntimeServices->GetVariable, 5,
			name, guid, 0, &data_size, data);
	dumphex(data, data_size);
	FreePool(data);
}

static EFI_STATUS set_pk(EFI_SYSTEM_TABLE *systab)
{
	struct {
		EFI_SIGNATURE_LIST sl;
		EFI_SIGNATURE_DATA sd;
		UINT8 cert[cert_size];
	} __attribute__((aligned (1))) __attribute__((packed)) data;

	data.sl.SignatureType = gEfiCertX509Guid;
	data.sl.SignatureListSize = sizeof(data);
	data.sl.SignatureHeaderSize = 0;
	data.sl.SignatureSize = sizeof(EFI_SIGNATURE_DATA) + cert_size;

	data.sd.SignatureOwner = gEfiImageSecurityDatabaseGuid; // random number
	CopyMem(data.cert, cert, cert_size);
	
	EFI_STATUS rc;
	Print(L"Clearing " EFI_PLATFORM_KEY_NAME);
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
				EFI_PLATFORM_KEY_NAME,
				&EfiGlobalVariable,
				EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|EFI_VARIABLE_BOOTSERVICE_ACCESS,
				0, NULL);
	Print(L"(%d)\n", rc);
	Print(L"Setting " EFI_PLATFORM_KEY_NAME);
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
				EFI_PLATFORM_KEY_NAME,
				&EfiGlobalVariable,
				EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|EFI_VARIABLE_BOOTSERVICE_ACCESS,
				sizeof(data), &data);
	Print(L"(%d)\n", rc);
	if (rc == EFI_SUCCESS)
		dumpvar(systab, &EfiGlobalVariable, EFI_PLATFORM_KEY_NAME);
	return rc;
}

static EFI_STATUS set_db(EFI_SYSTEM_TABLE *systab)
{
	// eddie:~/devel/github.com/pesign/src$ ./pesign -i clearpk.efi --hash
	// hash: 457d1d6e25d33b7fc5b0f51efeb14319ed438709
	
	char *hash0 = "\x50\x6d\xbb\x22\x87\x62\xe2\x56\xf2\xf9\xe4\x8e\x7b\xf9\x2d\x69\x7c\x31\xa7\x08";
	char *hash1 = "\x45\x7d\x1d\x6e\x25\xd3\x3b\x7f\xc5\xb0\xf5\x1e\xfe\xb1\x43\x19\xed\x43\x87\x09";

#define hash_size 20

	struct {
		EFI_SIGNATURE_LIST sl;
		EFI_SIGNATURE_DATA sd0;
		UINT8 sig0[hash_size];
		EFI_SIGNATURE_DATA sd1;
		UINT8 sig1[hash_size];
	} __attribute__((aligned (1))) __attribute__((packed)) data;

	data.sl.SignatureType = gEfiCertSha1Guid;
	data.sl.SignatureListSize = sizeof(data);
	data.sl.SignatureHeaderSize = 0;
	data.sl.SignatureSize = sizeof(EFI_SIGNATURE_DATA) + hash_size;

	data.sd0.SignatureOwner = gEfiImageSecurityDatabaseGuid; // bullshit
	CopyMem(data.sig0, hash0, hash_size);
	data.sd1.SignatureOwner = gEfiImageSecurityDatabaseGuid; // bullshit
	CopyMem(data.sig1, hash1, hash_size);
	
	EFI_STATUS rc;
	Print(L"Clearing " EFI_IMAGE_SECURITY_DATABASE);
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
				EFI_IMAGE_SECURITY_DATABASE,
				&gEfiImageSecurityDatabaseGuid,
				EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|EFI_VARIABLE_BOOTSERVICE_ACCESS,
				0, NULL);
	Print(L"(%d)\n", rc);
	Print(L"Setting " EFI_IMAGE_SECURITY_DATABASE);
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
				EFI_IMAGE_SECURITY_DATABASE,
				&gEfiImageSecurityDatabaseGuid,
				EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|EFI_VARIABLE_BOOTSERVICE_ACCESS,
				sizeof(data), &data);
	Print(L"(%d)\n", rc);
	if (rc == EFI_SUCCESS)
		dumpvar(systab, &gEfiImageSecurityDatabaseGuid,
				EFI_IMAGE_SECURITY_DATABASE);
	return rc;
}


EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc = EFI_SUCCESS;
	int i;

	InitializeLib(image, systab);

	rc = set_db(systab);
	if (rc != EFI_SUCCESS)
		return rc;
	rc = set_pk(systab);
	return rc;
}

