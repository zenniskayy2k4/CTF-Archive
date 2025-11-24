#!/usr/bin/env python3
from pwn import *
import hashlib, re

# --- elliptic curve code ---
def inverse(a, n): return pow(a, -1, n)
class EllipticCurve:
    def __init__(self,p,a,b,order=None): self.p,self.a,self.b,self.n=p,a,b,order
class ECPoint:
    def __init__(self,curve,x,y,inf=False):
        self.curve,self.x,self.y=curve,x%curve.p,y%curve.p
        if inf or not self.is_on_curve(): self.inf,self.x,self.y=True,0,0
        else: self.inf=False
    def is_on_curve(self):
        return (self.y*self.y-(self.x**3+self.curve.a*self.x+self.curve.b))%self.curve.p==0
    def copy(self): return ECPoint(self.curve,self.x,self.y,self.inf)
    def __neg__(self): return ECPoint(self.curve,self.x,-self.y,self.inf)
    def __add__(self,p2):
        p=self.curve.p
        if self.inf: return p2.copy()
        if p2.inf: return self.copy()
        if self.x==p2.x and (self.y+p2.y)%p==0: return ECPoint(self.curve,0,0,True)
        if self.x==p2.x: l=(3*self.x**2+self.curve.a)*inverse(2*self.y,p)%p
        else: l=(p2.y-self.y)*inverse(p2.x-self.x,p)%p
        x=(l*l-self.x-p2.x)%p; y=(l*(self.x-x)-self.y)%p
        return ECPoint(self.curve,x,y)
    def __sub__(self,p2): return self+(-p2)
    def __mul__(self,k):
        k=int(k); base=self.copy(); res=ECPoint(self.curve,0,0,True)
        while k>0:
            if k&1: res=res+base
            base=base+base; k>>=1
        return res
    __rmul__=__mul__

# --- curve params P-256 ---
p=0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a=-3
b=0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n=0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
curve=EllipticCurve(p,a,b,order=n)
G=ECPoint(curve,
 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)

def md5_int(m): return int(hashlib.md5(m).hexdigest(),16)
def parse_point(line):
    inside=line.strip().split("Point(")[1].rstrip(")")
    x,y=inside.split(","); return ECPoint(curve,int(x),int(y))

def main():
    io=remote("52.59.124.14",5050)

    io.recvuntil(b"My public key is:\n")
    pk_line=io.recvline().decode().strip()
    print("Public key:",pk_line)
    P_a=parse_point(pk_line)

    io.recvuntil(b"Choose an option:")
    io.sendline(b"2")

    # đọc cho tới khi gặp dòng có hex challenge
    chall_hex=None
    while chall_hex is None:
        line=io.recvline().decode().strip()
        print("DBG:",line)
        m=re.search(r"[0-9a-f]{32,}",line) # tìm chuỗi hex dài
        if m: chall_hex=m.group(0)

    chall_bytes=bytes.fromhex(chall_hex)
    z=md5_int(chall_bytes)%n

    R=(G*z)+P_a
    r=R.x%n; s_val=1
    sig=f"{r},{s_val}"
    print("Send forged sig:",sig)
    io.sendline(sig.encode())

    io.interactive()

if __name__=="__main__": main()