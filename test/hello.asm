bits 64

_start:
  mov rax, 0xa44434241
  push rax
  mov eax, 1
  mov edi, 1
  mov rsi, rsp
  mov edx, 5
  syscall
  add rsp, 8
