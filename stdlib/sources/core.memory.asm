option casemap:none
.code

PUBLIC stellar_v01_m636f72652e6d656d6f7279_s636f70795f7538_h003f5d2c0d82eadc
stellar_v01_m636f72652e6d656d6f7279_s636f70795f7538_h003f5d2c0d82eadc PROC
  test rcx, rcx
  jz memory_invalid
  test r8, r8
  jz memory_invalid
  cmp rdx, r9
  ja memory_bounds
  cmp rdx, 65536
  ja memory_bounds
  xor rax, rax
copy_loop:
  cmp rax, rdx
  jae copy_done
  mov r10b, byte ptr [rcx+rax]
  mov byte ptr [r8+rax], r10b
  inc rax
  jmp copy_loop
copy_done:
  ret
memory_bounds:
  mov rax, -21
  ret
memory_invalid:
  mov rax, -20
  ret
stellar_v01_m636f72652e6d656d6f7279_s636f70795f7538_h003f5d2c0d82eadc ENDP

PUBLIC stellar_v01_m636f72652e6d656d6f7279_s66696c6c5f7538_hafd0560a88b007b5
stellar_v01_m636f72652e6d656d6f7279_s66696c6c5f7538_hafd0560a88b007b5 PROC
  test rcx, rcx
  jz fill_invalid
  cmp rdx, 65536
  ja fill_bounds
  xor rax, rax
fill_loop:
  cmp rax, rdx
  jae fill_done
  mov byte ptr [rcx+rax], r8b
  inc rax
  jmp fill_loop
fill_done:
  ret
fill_bounds:
  mov rax, -21
  ret
fill_invalid:
  mov rax, -20
  ret
stellar_v01_m636f72652e6d656d6f7279_s66696c6c5f7538_hafd0560a88b007b5 ENDP

PUBLIC stellar_v01_m636f72652e6d656d6f7279_s657175616c5f7538_he940d3fecdfc62b9
stellar_v01_m636f72652e6d656d6f7279_s657175616c5f7538_he940d3fecdfc62b9 PROC
  test rcx, rcx
  jz equal_invalid
  test r8, r8
  jz equal_invalid
  cmp rdx, 65536
  ja equal_bounds
  cmp r9, 65536
  ja equal_bounds
  cmp rdx, r9
  jne equal_false
  xor rax, rax
equal_loop:
  cmp rax, rdx
  jae equal_true
  mov r10b, byte ptr [rcx+rax]
  cmp r10b, byte ptr [r8+rax]
  jne equal_false
  inc rax
  jmp equal_loop
equal_true:
  mov eax, 1
  ret
equal_false:
  xor eax, eax
  ret
equal_bounds:
  mov rax, -21
  ret
equal_invalid:
  mov rax, -20
  ret
stellar_v01_m636f72652e6d656d6f7279_s657175616c5f7538_he940d3fecdfc62b9 ENDP
END
