
#include <efi.h>
#include <efilib.h>

#include "sb.h"
#include "cert.h"

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
	EFI_STATUS rc;

	InitializeLib(image, systab);

	rc = uefi_call_wrapper(systab->RuntimeServices->SetVariable, 5,
				EFI_PLATFORM_KEY_NAME,
				&EfiGlobalVariable,
				EFI_VARIABLE_NON_VOLATILE,
				0, NULL);
	Print(L"rc: 0x%x\n", (int)rc);
	return rc;
}

