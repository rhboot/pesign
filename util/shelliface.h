#ifndef SHELLIFACE_H
#define SHELLIFACE_H 1

/* this whole file needs to be moved into gnu-efi */

#define EFI_SHELL_INTERFACE_GUID \
 { 0x47c7b223, 0xc42a, 0x11d2, {0x8e,0x57,0x00,0xa0,0xc9,0x69,0x72,0x3b } }

typedef enum {
	ARG_NO_ATTRIB         = 0x0,
	ARG_IS_QUOTED         = 0x1,
	ARG_PARTIALLY_QUOTED  = 0x2,
	ARG_FIRST_HALF_QUOTED = 0x4,
	ARG_FIRST_CHAR_IS_ESC = 0x8
} EFI_SHELL_ARG_INFO_TYPES;

struct _EFI_SHELL_ARG_INFO {
	UINT32 Attributes;
} PACKED ALIGNED(1);

typedef struct _EFI_SHELL_ARG_INFO EFI_SHELL_ARG_INFO;

struct _EFI_SHELL_INTERFACE {
	EFI_HANDLE		ImageHandle;
	EFI_LOADED_IMAGE	*Info;

	CHAR16			**Argv;
	UINTN			Argc;

	CHAR16			**RedirArgv;
	UINTN			RedirArgc;

	EFI_FILE		*StdIn;
	EFI_FILE		*StdOut;
	EFI_FILE		*StdErr;

	EFI_SHELL_ARG_INFO	*ArgInfo;

	BOOLEAN			EchoOn;
} PACKED ALIGNED(1);

typedef struct _EFI_SHELL_INTERFACE EFI_SHELL_INTERFACE;

extern EFI_GUID gEfiShellInterfaceGuid;

#endif /* SHELLIFACE_H */
