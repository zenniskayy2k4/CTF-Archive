#!/usr/bin/env python3

from Crypto.Util.number import *
from string import *
from flag import flag

def pad(flag):
	r = len(flag) % 8
	if r != 0:
		flag = flag[:-1] + (8 - r) * printable[:72][getRandomRange(0, 71)].encode() + flag[-1:]
	return flag

def genkey(nbit):
	e = getPrime(64)
	p, q = [getPrime(nbit) for _ in ':)']
	n = p * q
	return (e, n), (p, q)

def encrypt(msg, pubkey):
	e, n = pubkey
	msg = pad(msg)
	m = bytes_to_long(msg)
	c = pow(m, e, n)
	return c

nbit = 1024
pubkey, _ = genkey(nbit)

e, n = pubkey
print(f'n = {n}')
for _ in range(25):
	print(f'c = {encrypt(flag, (e, n))}')
	e += 2
print(f'e = {e}')