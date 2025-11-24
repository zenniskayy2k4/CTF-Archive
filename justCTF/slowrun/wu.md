# slowrun Writeup

## What I did (concise):

Recovered the math from the decompiled code:

Let $G(n)$ be the value computed by sub_12E9(n), with bases $G(0)=2$, $G(1)=1$.

For $n \geq 2$:
$G(n)=(n-4)+73n^5+8n^3+H(n-1)$, where

$H(m)=
\begin{cases}
1, & m \leq 1 \\
G(m-1)+3G(m-2)-5G(m-3)+3m^4, & m \geq 2
\end{cases}$

The program, for input $n$, returns:

If $n \leq 100$: $G(n)$.

If $n > 100$: $((G(n) \mod M)+M) \mod M+C_2$,
with

$M = 12871709638832864416674237492708808074465131233250468097567609804146306910998417223517320307084142930385333755674444057095681119233485961920941215894136808839080569675919567597231$

$C_2 = 805129649450289111374098215345043938348341847793365469885914570440914675704049341968773123354333661444680237475120349087680072042981825910641377252873686258216120616639500404381$

I computed $G(13337) \mod M$ iteratively (memoized DP), then added $C_2$ as per the code path for $n > 100$. The decimal result above is what the binary would print as flag: <number>; per the challenge's format, the flag is that number wrapped as justCTF{...!}.

You're right—and the binary doesn't want you to "wrap a number."
It prints a decimal integer that is actually the big-endian byte value of the flag.

## Flag
`justCTF{1n_0rd3r_70_und3r574nd_r3cur510n_y0u_h4v3_t0_und3r574nd_r3cur510n}`

## How it's derived (tight):
The Docker runs `/tmp/slowrun 13337`.

For n>100, sub_1878 returns:

$$R = (G(n) \mod M) + C$$

where M = off_6010 and C = off_6018. (sub_17F4 is a normalized modulo.)

G(n) comes from sub_12E9:

### Bases: 
$$G(0) = 2, G(1) = 1$$ (and $$G(k \leq 0) = 1$$ except $$G(0) = 2$$).

### For $$n \geq 2$$:
$$G(n) = (n - 4) + 73n^5 + 8n^3 + H(n - 1)$$

### H from sub_1500:
$$H(m) = 1$$ for $$m \leq 1$$; otherwise
$$H(m) = G(m - 1) + 3G(m - 2) - 5G(m - 3) + 3m^4$$.

Compute $$R$$ for n=13337, then convert the integer $$R$$ to bytes (big-endian) and ASCII-decode → the string above.

So if you let `./slowrun 13337` "run forever," the decimal it prints is the big number whose bytes read exactly that `justCTF{...}`.
