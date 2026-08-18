option casemap:none
.code

CHECKED_BIN MACRO symbol:req, instruction:req
LOCAL arithmetic_overflow, invalid_argument
PUBLIC symbol
symbol PROC
  test r8, r8
  jz invalid_argument
  mov eax, ecx
  instruction eax, edx
  jo arithmetic_overflow
  mov dword ptr [r8], eax
  xor eax, eax
  ret
arithmetic_overflow:
  mov eax, -12
  ret
invalid_argument:
  mov eax, -20
  ret
symbol ENDP
ENDM

WRAPPING_BIN MACRO symbol:req, instruction:req
LOCAL invalid_argument
PUBLIC symbol
symbol PROC
  test r8, r8
  jz invalid_argument
  mov eax, ecx
  instruction eax, edx
  mov dword ptr [r8], eax
  xor eax, eax
  ret
invalid_argument:
  mov eax, -20
  ret
symbol ENDP
ENDM

CHECKED_BIN stellar_v01_m636f72652e636865636b6564_s636865636b65645f6164645f693332_h52b4c2e029eebc48, add
CHECKED_BIN stellar_v01_m636f72652e636865636b6564_s636865636b65645f7375625f693332_h8f2dae1b82604733, sub
CHECKED_BIN stellar_v01_m636f72652e636865636b6564_s636865636b65645f6d756c5f693332_hbacd8e95a7fcf1c8, imul
WRAPPING_BIN stellar_v01_m636f72652e636865636b6564_s7772617070696e675f6164645f693332_h2a1d701b4059fe48, add
WRAPPING_BIN stellar_v01_m636f72652e636865636b6564_s7772617070696e675f7375625f693332_hc8519571415adde7, sub
WRAPPING_BIN stellar_v01_m636f72652e636865636b6564_s7772617070696e675f6d756c5f693332_h24fc628840faab5f, imul
END
