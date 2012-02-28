
#include <efi.h>
#include <efilib.h>

#include "sb.h"
#include "pk.h"

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

static EFI_STATUS set_kek(EFI_SYSTEM_TABLE *systab)
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
				EFI_KEY_EXCHANGE_KEY_NAME,
				&EfiGlobalVariable,
				EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|EFI_VARIABLE_BOOTSERVICE_ACCESS,
				0, NULL);
	Print(L"(%d)\n", rc);
	Print(L"Setting " EFI_PLATFORM_KEY_NAME);
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
				EFI_KEY_EXCHANGE_KEY_NAME,
				&EfiGlobalVariable,
				EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|EFI_VARIABLE_BOOTSERVICE_ACCESS,
				sizeof(data), &data);
	Print(L"(%d)\n", rc);
	if (rc == EFI_SUCCESS)
		dumpvar(systab, &EfiGlobalVariable, EFI_KEY_EXCHANGE_KEY_NAME);
	return rc;
}

/* PK is actually just the openssl bignum of M= from the pubkey, raw there
 * in the file, no DER or anything like that.  So you can get it from:
 * $ openssl rsa -inform PEM -in privkey.pem -modulus | grep Modulus | sed -e 's/Modulus=//' -e 's,..,\\x&,g' -e 's/$/"/' -e 's/^/char *pubkey="/'
 */
static EFI_STATUS set_pk(EFI_SYSTEM_TABLE *systab)
{
	struct {
		EFI_SIGNATURE_LIST sl;
		EFI_SIGNATURE_DATA sd;
		UINT8 cert[pk_size];
	} __attribute__((aligned (1))) __attribute__((packed)) data;

	data.sl.SignatureType = gEfiCertX509Guid;
	data.sl.SignatureListSize = sizeof(data);
	data.sl.SignatureHeaderSize = 0;
	data.sl.SignatureSize = sizeof(EFI_SIGNATURE_DATA) + pk_size;

	data.sd.SignatureOwner = gEfiImageSecurityDatabaseGuid; // random number
	CopyMem(data.cert, pk, pk_size);
	
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

	data.sd0.SignatureOwner = rh_guid;
	CopyMem(data.sig0, hash0, hash_size);
	data.sd1.SignatureOwner = rh_guid;
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
	if (rc != EFI_SUCCESS)
		return rc;

	rc = set_db(systab);
	if (rc != EFI_SUCCESS)
		return rc;

	rc = set_kek(systab);
	if (rc != EFI_SUCCESS)
		return rc;

	rc = set_pk(systab);
	return rc;
}

