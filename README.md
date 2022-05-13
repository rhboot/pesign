# pesign + efikeygen

Signing tools for PE-COFF binaries.  Compliant with the PE and Authenticode
specifications.

(These serve a similar purpose to Microsoft's
[SignTool.exe](http://msdn.microsoft.com/en-us/library/8s9b9yaz%28v=vs.80%29.aspx),
except for Linux.)

## Examples

Generate a key for use with pesign, stored on disk:

```
efikeyen -d /etc/pki/pesign -S -TYPE -c 'CN=Your Name Key' -n 'Custom Secureboot'
```

For more complex and secure use cases (e.g., hardware tokens), see
efikeygen man page (`man efikeygen`).

Sign a UEFI application using that key:

```
pesign -i grubx64.efi -o grubx64.efi.signed -c 'Custom Secureboot' -s
```

Show signatures on a UEFI application:

```
pesign -i grubx64.efi.signed -S
```

For more signing/verification operations, see the pesign man page (`man
pesign`).
