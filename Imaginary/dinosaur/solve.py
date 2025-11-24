import re
from itertools import islice

RAW = """
imagine: 10907
harold: 7824
roooreos: 4121
roofrozenvoid: 3984
roorobin: 3889
roonobooliet3rnos: 3780
kek: 3049
skullfire: 2900
why: 2369
rooheartet3rnos: 1796
breadthink: 1493
roozyphen: 815
roosunnobooli: 533
roobamboo: 472
roodevilet3rnos: 434
psyduck: 416
roowhim: 295
rooyayet3rnos: 292
aaaaa: 128
roorage: 83
2021_snowsgiving_emojis_002_snow: 81
programmer: 78
thisisfine: 77
bigbrain: 54
roohappy2: 44
gcloud: 41
roopuzzler7: 38
roocashet3rnos: 33
rooaz: 30
coolcry: 24
roomjkoo: 16
plus1: 14
roohappy3: 13
puzzler7: 12
tirefirenervous: 7
732334696565964811: 7
max49: 4
astrozoooom: 4
wut: 3
moaifire: 3
roostephencurry: 3
rooban: 2
roosupport: 2
roofrozen: 2
roomaxnobooli: 2
roopingmad: 1
roopuzzlerdevil: 1
""".strip()

Entry = tuple[str,int]

def parse(raw:str) -> list[Entry]:
    out = []
    for line in raw.splitlines():
        m = re.match(r'\s*([^:]+)\s*:\s*(\d+)\s*$', line)
        if not m: 
            continue
        name = m.group(1).strip()
        cnt = int(m.group(2))
        out.append((name, cnt))
    return out

def strip_roo(name:str) -> str:
    # bỏ tiền tố 'roo' nếu có (rất nhiều tên dạng đó)
    return re.sub(r'^roo+', '', name)

def leet(s:str) -> str:
    return (s.replace('0','o')
              .replace('1','l')
              .replace('3','e')
              .replace('4','a')
              .replace('5','s')
              .replace('7','t')
              .replace('_',''))

def mod_char(idx:int, s:str, one_based=False) -> str:
    if not s:
        return ''
    L = len(s)
    if one_based:
        k = (idx % L) or L
        return s[k-1]
    else:
        return s[idx % L]

def build(entries:list[Entry], *, order:str, transform, picker, limit=None) -> str:
    E = entries[:]
    if order == 'as_is':
        pass
    elif order == 'count_desc':
        E.sort(key=lambda x: x[1], reverse=True)
    elif order == 'count_asc':
        E.sort(key=lambda x: x[1])
    else:
        raise ValueError(order)
    if limit:
        E = list(islice(E, limit))
    chars = []
    for name, cnt in E:
        n2 = transform(name)
        ch = picker(n2, cnt)
        chars.append(ch)
    return ''.join(chars)

def try_all(entries:list[Entry]):
    orders = ['as_is', 'count_desc', 'count_asc']
    transforms = [
        ('raw', lambda s: s),
        ('strip_roo', strip_roo),
        ('strip_roo_leet', lambda s: leet(strip_roo(s))),
        ('leet', leet),
    ]
    pickers = [
        ('first', lambda s,c: s[:1] if s else ''),
        ('last',  lambda s,c: s[-1:] if s else ''),
        ('mod0',  lambda s,c: mod_char(c, s, one_based=False)),
        ('mod1',  lambda s,c: mod_char(c, s, one_based=True)),
        ('len_mod0', lambda s,c: mod_char(len(s), s, one_based=False)),
        ('len_mod1', lambda s,c: mod_char(len(s), s, one_based=True)),
    ]
    for order in orders:
        for tname, tf in transforms:
            for pname, pk in pickers:
                for limit in (None, 50, 100):
                    s = build(entries, order=order, transform=tf, picker=pk, limit=limit)
                    if any(tag in s.lower() for tag in ('ictf{','flag{','ctf{','imaginary{')):
                        print(f'[HIT] order={order} transform={tname} picker={pname} limit={limit}')
                        print(s)
                    # In các chuỗi ngắn đọc được
                    if len(s) <= 120:
                        # heuristic: có chữ cái thường và ngoặc nhọn
                        if '{' in s or '}' in s:
                            print(f'[MAYBE] order={order} transform={tname} picker={pname} limit={limit} -> {s}')

def decode_snowflake(x:int):
    # Discord snowflake -> timestamp
    epoch = 1420070400000  # 2015-01-01T00:00:00Z
    ts_ms = (x >> 22) + epoch
    return ts_ms

if __name__ == '__main__':
    entries = parse(RAW)
    try_all(entries)
    # Kiểm tra snowflake
    snow = next((int(n) for n,_ in entries if n.isdigit()), None)
    if snow:
        ts = decode_snowflake(snow)
        from datetime import datetime, timezone
        print('Snowflake ts:', datetime.fromtimestamp(ts/1000, tz=timezone.utc))