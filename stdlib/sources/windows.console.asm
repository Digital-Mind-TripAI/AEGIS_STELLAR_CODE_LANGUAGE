option casemap:none
EXTERN WriteFile:PROC
.code
; Descriptor-only capability source. Tranche 3 does not assemble, link, or run it.
PUBLIC stellar_windows_console_write_v01
stellar_windows_console_write_v01 PROC
  jmp WriteFile
stellar_windows_console_write_v01 ENDP
END
