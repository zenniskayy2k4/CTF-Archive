from Crypto.Util.number import *

def gcd_extended(a, b):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = gcd_extended(b % a, a)
        return (g, x - (b // a) * y, y)
    
    
m = 5 * 11 * 17
p1,p2,p3 = 5,11,17
a1,a2,a3 = 2,3,5
m1,m2,m3 = 11*17,5*17,5*11
y1,y2,y3 = inverse(m1,p1),inverse(m2,p2),inverse(m3,p3)
flag = (a1*m1*y1 + a2*m2*y2 + a3*m3*y3) % m
print(flag)
print((2*11*17*inverse(11*17,5) + 3*5*17*inverse(5*17,11) + 5*5*11*inverse(5*11,17)) % 935)