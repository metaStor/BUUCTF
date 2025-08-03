from pwn import *


r = remote('node5.buuoj.cn', 28619)

r.interactive()