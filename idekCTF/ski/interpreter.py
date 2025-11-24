import re
import sys
from dataclasses import dataclass
from functools import cache
from pathlib import Path


sys.setrecursionlimit(2_000_000)


class Term:
    __slots__ = ()


class _Const(Term):
    __slots__ = ('_name',)

    def __init__(self, n: str) -> None:
        self._name = n

    def __repr__(self) -> str:
        return self._name

    def __hash__(self) -> int:
        return hash(self._name)

    def __eq__(self, other: object) -> bool:
        return self is other


S = _Const('S')
K = _Const('K')
I = _Const('I')  # noqa: E741


@dataclass(frozen=True, slots=True)
class Var(Term):
    name: str

    def __repr__(self) -> str:
        return self.name


@dataclass(frozen=True, slots=True)
class App(Term):
    f: Term
    x: Term

    def __repr__(self) -> str:
        return f'({self.f} {self.x})'


def show(t: Term) -> str:
    if t is S:
        return 'S'
    if t is K:
        return 'K'
    if t is I:
        return 'I'
    if isinstance(t, Var):
        return t.name
    if isinstance(t, App):
        return f'({show(t.f)} {show(t.x)})'
    return '?'


TOKENS = [
    ('SPACE', r'[ \t\r\n]+'),
    ('LP', r'\('),
    ('RP', r'\)'),
    ('EQ', r'='),
    ('ID', r'[A-Za-z_][A-Za-z0-9_]*'),
]
Token = tuple[str, str, int]


def lex(src: str) -> list[Token]:
    pos = 0
    out: list[Token] = []

    rx = re.compile('|'.join(f'(?P<{n}>{r})' for n, r in TOKENS))
    while pos < len(src):
        m = rx.match(src, pos)
        if not m:
            frag = src[pos : pos + 20].replace('\n', ' ')
            raise SyntaxError(f'Lex error at {pos}: {frag!r}')

        typ, val = m.lastgroup, m.group()
        pos = m.end()
        if typ == 'SPACE':
            continue
        out.append((typ, val, pos))
    return out


class Parser:
    def __init__(self, toks: list[Token]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self, *k: str) -> Token | None:
        if self.i >= len(self.toks):
            return None
        t, v, p = self.toks[self.i]
        if not k or t in k or v in k:
            return (t, v, p)
        return None

    def eat(self, *k: str) -> Token | None:
        t = self.peek(*k)
        if not t:
            want = ' or '.join(k) if k else '(any)'
            got = self.toks[self.i] if self.i < len(self.toks) else 'EOF'
            raise SyntaxError(f'Parse error: expected {want}, got {got}')
        self.i += 1
        return t

    def parse_program(self) -> list[tuple[str, ...]]:
        items: list[tuple[str, ...]] = []
        while self.i < len(self.toks):
            if self.peek('ID') and self.i + 1 < len(self.toks) and self.toks[self.i + 1][0] == 'EQ':
                name = self.eat('ID')[1]
                self.eat('EQ')
                items.append(('def', name, self.parse_term()))
            else:
                items.append(('term', self.parse_term()))
        return items

    def parse_term(self) -> 'Term':
        level: list[list[Term]] = [[]]

        while self.i < len(self.toks):
            if self.peek('LP'):
                self.eat('LP')
                level.append([])
                continue

            if self.peek('RP'):
                self.eat('RP')
                if len(level) == 1:
                    break
                finished = self._chain(level.pop())
                level[-1].append(finished)
                continue

            if self.peek('ID'):
                _, name, _ = self.eat('ID')
                if name == 'S':
                    term = S
                elif name == 'K':
                    term = K
                elif name == 'I':
                    term = I
                else:
                    term = Var(name)
                level[-1].append(term)
                continue

            break

        return self._chain(level.pop())

    @staticmethod
    def _chain(ts: list['Term']) -> 'Term':
        if not ts:
            raise SyntaxError
        res = ts[0]
        for a in ts[1:]:
            res = App(res, a)
        return res


def parse(src: str) -> list[tuple[str, ...]]:
    return Parser(lex(src)).parse_program()


def prelude(flag: str, max_bits: int = 128 * 8) -> dict[str, Term]:
    bits = []
    for b in flag.encode():
        bits.extend((b >> i) & 1 for i in range(7, -1, -1))
        if len(bits) >= max_bits:
            break
    bits.extend([0] * (max_bits - len(bits)))
    return {f'_F{i}': (K if bit else App(K, I)) for i, bit in enumerate(bits[:max_bits])}


def substitute(t: Term, env: dict[str, Term], cache: dict[Term, Term] | None = None) -> Term:
    if cache is None:
        cache = {}

    if t in cache:
        return cache[t]

    if t is S or t is K or t is I:
        cache[t] = t
        return t

    if isinstance(t, Var):
        res = substitute(env[t.name], env, cache) if t.name in env else t
        cache[t] = res
        return res

    if isinstance(t, App):
        f_new = substitute(t.f, env, cache)
        x_new = substitute(t.x, env, cache)
        res = t if (f_new is t.f and x_new is t.x) else App(f_new, x_new)
        cache[t] = res
        return res

    raise TypeError(t)


def _rebuild(head: Term, args: list[Term]) -> Term:
    for a in args:
        head = App(head, a)
    return head


def _flatten(t: Term) -> tuple[Term, list[Term]]:
    args: list[Term] = []
    while isinstance(t, App):
        args.append(t.x)
        t = t.f
    args.reverse()
    return t, args


def _step(t: Term) -> Term | None:
    head, args = _flatten(t)

    if head is I and args:
        return _rebuild(args[0], args[1:])

    if head is K and len(args) >= 2:
        return _rebuild(args[0], args[2:])

    if head is S and len(args) >= 3:
        f, g, x, *rest = args
        return _rebuild(App(App(f, x), App(g, x)), rest)

    if isinstance(head, App):
        h2 = _step(head)
        if h2 is not None:
            return _rebuild(h2, args)

    for i, a in enumerate(args):
        if isinstance(a, App):
            a2 = _step(a)
            if a2 is not None:
                args = args.copy()
                args[i] = a2
                return _rebuild(head, args)

    return None


@cache
def normal_form(t: Term) -> tuple[Term, int]:
    steps = 0
    cur = t
    while True:
        nxt = _step(cur)
        if nxt is None:
            return cur, steps
        cur = nxt
        steps += 1


def main() -> None:
    with Path('./program.txt').open() as f:
        src = f.read()

    print('₍^. .^₎⟆')
    flag = input().strip()

    print('parsing')
    items = parse(src)
    env = prelude(flag)
    last_term = None

    for it in items:
        if it[0] == 'def':
            _, name, term_ast = it
            env[name] = substitute(term_ast, env)
        else:
            _, term_ast = it
            last_term = substitute(term_ast, env)

    print('reducing to normal form')
    nf, steps = normal_form(last_term)
    print(f'reduced in {steps} steps!')
    print(f'- nf: {show(nf)}')

    if nf is K:
        print('- flag: correct')
    elif isinstance(nf, App) and nf.f is K and nf.x is I:
        print('- flag: incorrect')
    else:
        print('- flag: unknown status (did you mess something up?)')


if __name__ == '__main__':
    main()
