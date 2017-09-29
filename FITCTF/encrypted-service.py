#!/usr/bin/env python

# FIT CTF
# Crypto (encrypted service-200) Write-up
# fatihdasgin

from pwn import *
#import time
#import socket


host="walked.problem.ctf.nw.fit.ac.jp"
port=4000

enc = "556d633950513d3d5632463a51523e3e586d473b52533f3f5d5b663c535440405e4a493d545541415e364a3e555642425d4e693f565743435b724c40575844445f744d415859454560516c42595a464661776d435a5b4747627650445b5c4848653f6f455c5d4949675570465d5e4a4a656453475e5f4b4b687a54485f604c4c6758734960614d4d6569744a61624e4e6669754b62634f4f6c43584c636450506e80594d64655151"
n = 16
enc1 = [enc[i:i+n] for i in range(0, len(enc), n)]

ALPHABET = "ABCDEFGHIJKLMNOPRSTUVYZQWXabcdefghijklmnoprstuvyzqwx0123456789_{}[]-?."
flag=""

r = remote(host,port)

for i in range(1,22):
	offset = enc1[int(i-1)]
	for j in ALPHABET:
		pp = str(j)*i
		r.sendline(pp)
		data = r.recvuntil("\n",timeout=5)[(16*int(i-1)):(16*int(i))]
		if offset == data:
			flag += j
			break

r.close()

print flag
