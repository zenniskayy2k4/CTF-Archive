# Source Generated with Decompyle++
# File: pylinguese.pyc (Python 3.12)

import pyfiglet
file = open('flag.txt', 'r')
flag = file.read()
font = 'slant'
words = 'MASONCC IS THE BEST CLUB EVER'
flag_track = 0
art = list(pyfiglet.figlet_format(words, font = font))
i = len(art) % 10
for ind in range(len(art)):
    if not ind == i:
        continue
    if not flag_track < len(flag):
        continue
    art[ind] = flag[flag_track]
    i += 28
    flag_track += 1
art_str = ''.join(art)
first_val = 5
second_val = 6
first_half = art_str[:len(art_str) // 2]
second_half = art_str[len(art_str) // 2:]
# WARNING: Decompyle incomplete
