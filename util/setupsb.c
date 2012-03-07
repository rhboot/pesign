
#include <efi.h>
#include <efilib.h>

#include "shelliface.h"
#include "sb.h"

/* XXX probably shouldn't ship defaulting to this */
EFI_GUID rh_guid = {0xade9e48f, 0x9cb8, 0x98e6, {0x31,0xaf,0xb4,0xe6,0x00,0x9e,0x2f,0xe3}};

/* XXX this needs to be moved into gnu-efi */
EFI_GUID gEfiShellInterfaceGuid = EFI_SHELL_INTERFACE_GUID;

/* XXX this needs to be moved into gnu-efi */
#define EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS			0x00000010
#define EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS	0x00000020
#define EFI_VARIABLE_APPEND_WRITE				0x00000040

/* XXX this needs to be moved into gnu-efi */
#define EFI_SHELL_DEVICE_PATH_MAP \
 {0x47c7b225, 0xc42a, 0x11d2, {0x8e,0x57,0x0,0xa0,0xc9,0x69,0x72,0x3b}}
EFI_GUID gEfiShellDevPathMap = EFI_SHELL_DEVICE_PATH_MAP;

static void
__attribute__((unused))
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
__attribute__((unused))
dumphex_str(CHAR16 *data, UINTN data_size)
{
	int i, j;
	for (i = 0, j = 0; i < data_size; i+=2, j++) {
		Print(L"%c%c ", data[i], data[i+1]);
		if (j == 15) {
			j = -1;
			Print(L"\n");
		}
	}
	if (j != -1)
		Print(L"\n");
}

static EFI_STATUS
get_args(EFI_HANDLE image, UINTN *argc, CHAR16 ***argv)
{
	EFI_STATUS rc;
	EFI_SHELL_INTERFACE *shell;

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

static int
pk_is_populated(void)
{
	char *data = NULL;
	UINTN data_size = 0;

	data = LibGetVariableAndSize(EFI_PLATFORM_KEY_NAME, &EfiGlobalVariable,
		&data_size);
	FreePool(data);
	if (!data || data_size == 0)
		return 0;
	return 1;
}

static int
kek_is_populated(void)
{
	char *data = NULL;
	UINTN data_size = 0;

	data = LibGetVariableAndSize(EFI_KEY_EXCHANGE_KEY_NAME,
		&EfiGlobalVariable, &data_size);
	FreePool(data);
	if (!data || data_size == 0)
		return 0;
	return 1;
}

static int
db_is_populated(void)
{
	char *data = NULL;
	UINTN data_size = 0;

	data = LibGetVariableAndSize(EFI_IMAGE_SECURITY_DATABASE,
		&gEfiImageSecurityDatabaseGuid, &data_size);
	FreePool(data);
	if (!data || data_size == 0)
		return 0;
	return 1;
}

#if 0 /* doesn't appear necessary */
static int
dbx_is_populated(void)
{
	char *data = NULL;
	UINTN data_size = 0;

	data = LibGetVariableAndSize(EFI_IMAGE_SECURITY_DATABASE1,
		&gEfiImageSecurityDatabaseGuid, &data_size);
	FreePool(data);
	if (!data || data_size == 0)
		return 0;
	return 1;
}
#endif

static EFI_STATUS
make_variable(UINT8 *hash, UINTN hash_size,
		EFI_GUID owner, EFI_GUID signature_type,
		VOID **data, UINTN *data_size)
{
	if (!data || !data_size)
		return EFI_INVALID_PARAMETER;

	struct {
		EFI_SIGNATURE_LIST sl;
		EFI_SIGNATURE_DATA sd;
		UINT8 cert[hash_size];
	} __attribute__((aligned (1))) __attribute__((packed)) *var;

	var = AllocatePool(sizeof(*var));
	if (!var)
		return EFI_OUT_OF_RESOURCES;

	var->sl.SignatureType = signature_type;
	var->sl.SignatureListSize = sizeof(*var);
	var->sl.SignatureHeaderSize = 0;
	var->sl.SignatureSize = sizeof(EFI_SIGNATURE_DATA) + hash_size;

	var->sd.SignatureOwner = owner;
	CopyMem(var->cert, hash, hash_size);

	*data = var;
	*data_size = sizeof(*var);

	return EFI_SUCCESS;
}

static void
usage(void)
{
	Print(L"Usage: setupbs COMMAND \n");
	Print(L"  COMMAND := { set KEY SET_OPTIONS |\n"
	      L"               append KEY SET_OPTIONS |\n"
	      L"               clear KEY CLEAR_OPTIONS |\n"
	      L"               help }\n");
	Print(L"  KEY := { pk | kek | db | dbx }\n");
	Print(L"  SET_OPTIONS := [ --force ] { HASH | FILE }\n");
	Print(L"  HASH := --hash SIG_TYPE <hash>\n");
	Print(L"  FILE := --file SIG_TYPE <filename>\n");
	Print(L"  SIG_TYPE := sha1 sha256 rsa2048 x509\n");
	Print(L"  CLEAR_OPTIONS := [ --force ]\n");
}

static int
has_force(UINTN argc, CHAR16 **argv)
{
	int i;
	for (i = 0; i < argc; i++) {
		if (!StrCmp(argv[i], L"--force"))
			return 1;
	}
	return 0;
}

static inline int
hex_to_ord(CHAR16 x)
{
	char y = x & 0xff;
	int c = y >= 'a' ? 'a'-0xa
			 : y >= 'A' ? 'A'-0xa
			 	    : '0';
	y -= c;
	
	if (y < 0 && y > 0xf)
		return -1;
	return y;
}

static struct {
	CHAR16 *name;
	EFI_GUID guid;
	UINTN size;
} hashes[] = {
	{ L"SHA1", EFI_CERT_SHA1_GUID, 20 },
	{ L"SHA256", EFI_CERT_SHA256_GUID, 32 },
	{ L"RSA2048", EFI_CERT_RSA2048_GUID, 256 },
	{ L"X509", EFI_CERT_X509_GUID, -1 },
	{ NULL, }
};

static EFI_STATUS
get_hash(UINTN argc, CHAR16 **argv, EFI_GUID *sig_type_guid,
	UINT8 **hashp, UINTN *hash_sizep)
{
	int i;

	UINT8 *hash = NULL;
	UINTN hash_size = 0;

	EFI_GUID hash_guid;
	UINTN expected_hash_size = 0;

	if (!hashp || !hash_sizep)
		return EFI_INVALID_PARAMETER;

	for (i = 1; i < argc; i++) {
		if (!StrCmp(argv[i], L"--hash")) {
			if (argc <= i+2) {
				Print(L"argc is %d and we need %d\n",
					argc, i+2);
				return EFI_INVALID_PARAMETER;
			}

			StrUpr(argv[i+1]);
			int j;
			for (j = 0; hashes[j].name != NULL; j++) {
				if (!StrCmp(hashes[j].name, argv[i+1])) {
					hash_guid = hashes[j].guid;
					expected_hash_size = hashes[j].size;
					break;
				}
			}

			if (!expected_hash_size) {
				Print(L"Unknown hash %s\n", argv[i+1]);
				return EFI_UNSUPPORTED;
			}

			CHAR16 *text = argv[i+2];
			int text_len = StrLen(text);

			hash_size = text_len / 2;
			if (hash_size != expected_hash_size) {
				Print(L"Hash size was expected to be %d, but was actually %d\n", expected_hash_size, hash_size);
				return EFI_INVALID_PARAMETER;
			}


			hash = AllocatePool(hash_size);
			int k;
			for (j = 0, k = 0; j < hash_size; j++, k+=2) {
				int x = hex_to_ord(text[k]);
				int y = hex_to_ord(text[k+1]);

				if (x < 0 || y < 0) {
					Print(L"Coding error: {%d,%d} should both be positive\n", x, y);
					FreePool(hash);
					return EFI_INVALID_PARAMETER;
				}
				hash[j] = (x << 4) | y;
			}

			*sig_type_guid = hash_guid;
			*hashp = hash;
			*hash_sizep = hash_size;
			return EFI_SUCCESS;
		}
	}
	return EFI_NOT_FOUND;
}

static EFI_STATUS
get_file(UINTN argc, CHAR16 **argv, EFI_GUID *sig_type_guid,
		UINT8 **hashp, UINTN *hash_sizep)
{
	return EFI_UNSUPPORTED;
}

static EFI_STATUS
set_pk(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	EFI_STATUS rc;
	UINT8 *hash = NULL;
	UINTN hash_size = 0;
	EFI_GUID sig_type_guid;

	rc = get_hash(argc, argv, &sig_type_guid, &hash, &hash_size);
	if (rc == EFI_NOT_FOUND) {
		rc = get_file(argc, argv, &sig_type_guid, &hash, &hash_size);
		if (rc == EFI_NOT_FOUND)
			return EFI_INVALID_PARAMETER;
	}
	if (EFI_ERROR(rc))
		return rc;

	if (!CompareMem(&sig_type_guid, &gEfiCertRsa2048Guid,
			sizeof(sig_type_guid))) {
		Print(L"PK must be an RSA2048 Modulus.\n");
		return EFI_INVALID_PARAMETER;
	}

	UINTN flags = EFI_VARIABLE_NON_VOLATILE |
				EFI_VARIABLE_RUNTIME_ACCESS |
				EFI_VARIABLE_BOOTSERVICE_ACCESS;
			
#if 0 /* this is what you'd expect */
	VOID *data = NULL;
	UINTN data_size = 0;

	rc = make_variable(hash, hash_size, rh_guid,
		sig_type_guid, &data, &data_size);

	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
			EFI_PLATFORM_KEY_NAME, &EfiGlobalVariable, 
			flags, data_size, data);
	FreePool(data);
#else /* this is what you get */
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
			EFI_PLATFORM_KEY_NAME, &EfiGlobalVariable, 
			flags, hash_size, hash);
#endif

	FreePool(hash);

	return rc;
}

static EFI_STATUS
set_db_helper(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image,
		UINTN argc, CHAR16 **argv,
		EFI_GUID *vendor_guid, CHAR16 *dbname,
		int append)
{
	EFI_STATUS rc;
	UINT8 *hash = NULL;
	UINTN hash_size = 0;
	EFI_GUID sig_type_guid;

	rc = get_hash(argc, argv, &sig_type_guid, &hash, &hash_size);
	if (rc == EFI_NOT_FOUND) {
		rc = get_file(argc, argv, &sig_type_guid, &hash, &hash_size);
		if (rc == EFI_NOT_FOUND)
			return EFI_INVALID_PARAMETER;
	}
	if (EFI_ERROR(rc))
		return rc;

	VOID *data = NULL;
	UINTN data_size = 0;

	rc = make_variable(hash, hash_size, rh_guid,
		sig_type_guid, &data, &data_size);

	UINTN flags = EFI_VARIABLE_NON_VOLATILE |
				EFI_VARIABLE_RUNTIME_ACCESS |
				EFI_VARIABLE_BOOTSERVICE_ACCESS;
	if (append)
		flags |= EFI_VARIABLE_APPEND_WRITE;
			
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
			dbname, vendor_guid, flags, data_size, data);
	FreePool(data);
	FreePool(hash);

	return rc;
}

static EFI_STATUS
set_db(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	return set_db_helper(systab, image, argc, argv,
				&gEfiImageSecurityDatabaseGuid,
				EFI_IMAGE_SECURITY_DATABASE, 0);
}

static EFI_STATUS
set_dbx(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	return set_db_helper(systab, image, argc, argv,
				&gEfiImageSecurityDatabaseGuid,
				EFI_IMAGE_SECURITY_DATABASE1, 0);
}

static EFI_STATUS
set_kek(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	return set_db_helper(systab, image, argc, argv,
				&EfiGlobalVariable,
				EFI_KEY_EXCHANGE_KEY_NAME, 0);
}

static EFI_STATUS
append_db(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{

	return set_db_helper(systab, image, argc, argv,
				&gEfiImageSecurityDatabaseGuid,
				EFI_IMAGE_SECURITY_DATABASE, 1);
}

static EFI_STATUS
append_dbx(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	return set_db_helper(systab, image, argc, argv,
				&gEfiImageSecurityDatabaseGuid,
				EFI_IMAGE_SECURITY_DATABASE1, 1);
}

static EFI_STATUS
append_kek(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	return set_db_helper(systab, image, argc, argv,
				&EfiGlobalVariable,
				EFI_KEY_EXCHANGE_KEY_NAME, 1);
}

static EFI_STATUS
append_pk(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	Print(L"PK Can only be one entry.\n");
	return EFI_UNSUPPORTED;
}

static EFI_STATUS
clear_pk(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	EFI_STATUS rc;
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
		EFI_PLATFORM_KEY_NAME, &EfiGlobalVariable,
		EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		0, NULL);
	if (rc == EFI_NOT_FOUND)
		rc = EFI_SUCCESS;
	return rc;
}

static EFI_STATUS
clear_db(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	EFI_STATUS rc;

	if (pk_is_populated() && !kek_is_populated() && !has_force(argc,argv)) {
		Print(L"Cowardly refusing to clear db with PK set "
			L"and no KEK\n");
		return EFI_UNSUPPORTED;
	}
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
		EFI_IMAGE_SECURITY_DATABASE, &gEfiImageSecurityDatabaseGuid,
		EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		0, NULL);
	if (rc == EFI_NOT_FOUND)
		rc = EFI_SUCCESS;
	return rc;
}

static EFI_STATUS
clear_dbx(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	EFI_STATUS rc;
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
		EFI_IMAGE_SECURITY_DATABASE1, &gEfiImageSecurityDatabaseGuid,
		EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		0, NULL);
	if (rc == EFI_NOT_FOUND)
		rc = EFI_SUCCESS;
	return rc;
}

static EFI_STATUS
clear_kek(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv)
{
	EFI_STATUS rc;
	if (pk_is_populated() && !db_is_populated() && !has_force(argc,argv)) {
		Print(L"Cowardly refusing to clear KEK with PK set "
			L"and no DB entries\n");
		return EFI_UNSUPPORTED;
	}
	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
		EFI_KEY_EXCHANGE_KEY_NAME, &EfiGlobalVariable,
		EFI_VARIABLE_NON_VOLATILE|EFI_VARIABLE_RUNTIME_ACCESS|
			EFI_VARIABLE_BOOTSERVICE_ACCESS,
		0, NULL);
	if (rc == EFI_NOT_FOUND)
		rc = EFI_SUCCESS;
	return rc;
}

struct {
	CHAR16 *name;
	CHAR16 *db;
	EFI_STATUS (*handler)(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv);
} actions[] = {
	{ L"set", L"pk", set_pk},
	{ L"set", L"kek", set_kek},
	{ L"set", L"db", set_db},
	{ L"set", L"dbx", set_dbx},
	{ L"append", L"PK", append_pk},
	{ L"append", L"kek", append_kek},
	{ L"append", L"db", append_db},
	{ L"append", L"dbx", append_dbx},
	{ L"clear", L"pk", clear_pk},
	{ L"clear", L"kek", clear_kek},
	{ L"clear", L"db", clear_db},
	{ L"clear", L"dbx", clear_dbx},
	{ NULL, NULL, NULL},
};

typedef EFI_STATUS (*handler)(EFI_SYSTEM_TABLE *systab, EFI_HANDLE image, UINTN argc, CHAR16 **argv);

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	UINTN argc;
	CHAR16 **argv;
	EFI_STATUS rc = EFI_SUCCESS;

	InitializeLib(image, systab);

	rc = get_args(image, &argc, &argv);
	if (EFI_ERROR(rc)) {
		Print(L"Error: %d\n", rc);
		return rc;
	}

	if (argc == 1) {
		Print(L"Too few arguments.\n");
show_usage:
		usage();
		return EFI_INVALID_PARAMETER;
	}

	if (argc == 2) {
		if (!StrCmp(argv[1], L"help") ||
				!StrCmp(argv[1], L"/help") ||
				!StrCmp(argv[1], L"--help") ||
				!StrCmp(argv[1], L"-?")) {
			usage();
			return EFI_SUCCESS;
		}
		goto show_usage;
	}

	int i = 1;

	rc = EFI_INVALID_PARAMETER;
	int j;

	for(j = 0; actions[j].name != NULL; j++ ) {
		if (!StrCmp(actions[j].name, argv[i]) &&
				!StrCmp(actions[j].db, argv[i+1])) {
			rc = actions[j].handler(systab, image, argc-i, argv+i);
			break;
		}
	}
	if (rc == EFI_UNSUPPORTED || rc == EFI_INVALID_PARAMETER)
		goto show_usage;

	if (EFI_ERROR(rc))
		Print(L"Error: %d\n", rc);
	return rc;
}
