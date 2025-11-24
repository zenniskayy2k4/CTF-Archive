```bash
zenniskayy@ZennisKayy:/mnt/e/Cyber Security/CTF/PatriotCTF/Burger King$ ./bkcrack.exe -C BurgerKing.zip -c Hole.svg -p partial.svg
bkcrack 1.8.1 - 2025-10-25
[10:49:32] Z reduction using 32 bytes of known plaintext
100.0 % (32 / 32)
[10:49:32] Attack on 240166 Z values at index 6
Keys: b9540c69 069a11f9 fd31648f
71.3 % (171295 / 240166)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 171295
[10:51:59] Keys
b9540c69 069a11f9 fd31648f
zenniskayy@ZennisKayy:/mnt/e/Cyber Security/CTF/PatriotCTF/Burger King$ ./bkcrack.exe -C BurgerKing.zip -k b9540c69 069a11f9 fd31648f -U unlock.zip 123
bkcrack 1.8.1 - 2025-10-25
[10:53:43] Writing unlocked archive unlock.zip with password "123"
100.0 % (5 / 5)
Wrote unlocked archive.
zenniskayy@ZennisKayy:/mnt/e/Cyber Security/CTF/PatriotCTF/Burger King$
```