# PWN 资源整理

## 基础库文件（libc）
- libc-2.23_32.so
- libc-2.23_64.so
- libc-2.32-3.1.x86_64.so
- libc.so.6
- libc6-amd64_2.34-3_i386.so
- libc6-i386_2.27-3ubuntu1_amd64.so
- libc6-i386_2.40-4_amd64.so
- libc6_2.23-0ubuntu11_amd64.so
- libc6_2.27-0ubuntu3_amd64.so
- libc6_2.30-7_i386.so
- libc6_2.40-4_i386.so
- ubuntu-16.4-libc-2.23.so

## 防护绕过（bypass_canary）
- bjdctf_2020_babyrop2
- others_babystack

## 堆漏洞（heap）
- Use_After_Free
  - hacknote.eddx
  - hacknote
- babyheap_0ctf_2017

## 内存保护（mprotect）
- get_started_3dsctf_2016
- inndy_rop
- not_the_same_3dsctf_2016
- ropexample

## Shellcode 利用（ret2shellcode）
- ez_pz_hackover_2016
- mrctf2020_shellcode
- syscallexample
- PicoCTF_2018_shellcode
- ciscn_2019_s_9
- pwnable_start
- mrctf2020_shellcode_revenge
- x_ctf_b0verfl0w

## ORW
- pwnable_orw (orw)
- [极客大挑战 2019]Not Bad (orw)
- ezshellcode

## 直接返回文本（ret2text）
- courage

## ROP 技术（rop）
- 2018_rop
- baby_rop
- baby_rop2
- babyrop_pwn（ROP32）
- bjdctf_2020_babyrop
- ciscn_2019_c_1（ROP64）
- jarvisoj_level4
- level3
- level3_x64
- rop_execve
- simplerop
- xdctf2015_pwn200
- jarvisoj_level5

## SROP 技术（srop）
- ciscn_s_3
- ciscn_2019_es_7

## 栈迁移（stack pivoting）
#### 迁移到bss+有两个读入函数的栈迁移
- [Black Watch 入群题]PWN_spwn
- gyctf_2020_borrowstack
- other_gyctf_2020_borrowstack
#### 泄露buf地址+在原来的栈上进行栈迁移
- ciscn_2019_es_2
- ciscn_s_4 (同ciscn_2019_es_2)
- actf_2019_babystack
#### 迁移到bss+只有一个读入函数的栈迁移
- leave

## 字符串格式化漏洞（fmt）
- [第五空间2019 决赛]PWN5
- fm
- axb_2019_fmt32
- wdb_2018_2nd_easyfmt
- mrctf2020_easy_equation
- inndy_echo
- axb_2019_fmt64
- fmt