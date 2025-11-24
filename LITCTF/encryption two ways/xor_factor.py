#!/usr/bin/env python3

import math
import sys

def check_cong(k, p, q, n, xored=None):
    kmask = (1 << k) - 1
    p &= kmask
    q &= kmask
    n &= kmask
    pqm = (p*q) & kmask
    return pqm == n and (xored is None or (p^q) == (xored & kmask))

def extend(k, a):
    kbit = 1 << (k-1)
    assert a < kbit
    yield a
    yield a | kbit

def factor(n, p_xor_q):
    tracked = set([(p, q) for p in [0, 1] for q in [0, 1]
                   if check_cong(1, p, q, n, p_xor_q)])

    PRIME_BITS = int(math.ceil(math.log(n, 2)/2))

    maxtracked = len(tracked)
    for k in range(2, PRIME_BITS+1):
        newset = set()
        for tp, tq in tracked:
            for newp_ in extend(k, tp):
                for newq_ in extend(k, tq):
                    # Remove symmetry
                    newp, newq = sorted([newp_, newq_])
                    if check_cong(k, newp, newq, n, p_xor_q):
                        newset.add((newp, newq))

        tracked = newset
        if len(tracked) > maxtracked:
            maxtracked = len(tracked)
    print('Tracked set size: {} (max={})'.format(len(tracked), maxtracked))

    # go through the tracked set and pick the correct (p, q)
    for p, q in tracked:
        if p != 1 and p*q == n:
            return p, q

    assert False, 'factors were not in tracked set. Is your p^q correct?'

def main():
    # if len(sys.argv) != 3:
    #     print('Usage: xor_factor.py n p_xor_q', file=sys.stderr)
    #     print('(give both numbers in decimal)', file=sys.stderr)

    n = 15743749539296409634663424121280780137241091382693667702428459710350799988364206067386721771957566782759869049232956203164038880156911093552224029889115066342065167950865082886553987387676830751986436049339135431329680104325633680830079626081064732539895004309746439339464459693383082656000036207580730478400742945792833119299470608434720699402585565729587072933594242753293708783340966330892945616957505604652405874136389552304994271320951778239892061518891595360471182332599388638905448501774287058774862731780749187489445130626995755810843627861024383386053591739555428660621596009796747521186540907587626526354979
    p_xor_q = 652894033279962566425008186365092838893869725740262193641304534232619908459893676704202466701334996356839920022055407472125920159605385058277557576760527691533492313754846196845213518864374872495789246833589664601461011666628560340498093906875153420704151856647622983700343126711039555765774571074223410682

    p, q = factor(n, p_xor_q)
    print(p)
    print(q)

if __name__ == '__main__':
    main()
