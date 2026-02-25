import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ACTION_RE = re.compile(r"{{-?\s*(.*?)\s*-?}}")
DEFINE_RE = re.compile(r'^define\s+"([^"]+)"')
INCLUDE_RE = re.compile(r'include\s+"([^"]+)"')
INPUT_RE = re.compile(r'index\s+\$provisions\s+\$logbook')
OUT_C_RE = re.compile(r'printf\s+"%s%c"\s+\$cargo')
OUT_S_RE = re.compile(r'printf\s+"%s%s"\s+\$cargo')
IF_OPEN_RE = re.compile(r'^(if|range|with|define|block)\b')
END_RE = re.compile(r'^end\b')

@dataclass
class Tpl:
    name: str
    start_line: int
    end_line: int
    text: str
    includes: list[str] = field(default_factory=list)
    input_reads: int = 0
    outputs: int = 0
    loop_guards: int = 0
    helm_moves: list[int] = field(default_factory=list)

def net_helm_delta(expr: str) -> int | None:
    # Handles common obfuscations:
    #   $helm = add $helm 1
    #   $helm = sub $helm 1
    #   $helm = sub (add $helm A) B  => +A-B
    #   $helm = add (sub $helm A) B  => -A+B
    expr = expr.strip()

    m = re.search(r'^\$helm\s*=\s*add\s+\$helm\s+(\d+)\s*$', expr)
    if m: return int(m.group(1))

    m = re.search(r'^\$helm\s*=\s*sub\s+\$helm\s+(\d+)\s*$', expr)
    if m: return -int(m.group(1))

    m = re.search(r'^\$helm\s*=\s*sub\s+\(add\s+\$helm\s+(\d+)\)\s+(\d+)\s*$', expr)
    if m: return int(m.group(1)) - int(m.group(2))

    m = re.search(r'^\$helm\s*=\s*add\s+\(sub\s+\$helm\s+(\d+)\)\s+(\d+)\s*$', expr)
    if m: return -int(m.group(1)) + int(m.group(2))

    # $helm = sub $helm (add 0 1)
    if "sub $helm (add 0 1)" in expr: return -1
    # $helm = add $helm (sub 2 1)
    if "add $helm (sub 2 1)" in expr: return +1

    return None

def parse_defines(path: Path) -> dict[str, Tpl]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines(True)
    defines: dict[str, Tpl] = {}

    in_def = False
    depth = 0
    cur_name = None
    cur_start = 0
    cur_buf: list[str] = []

    for i, line in enumerate(lines, start=1):
        actions = ACTION_RE.findall(line)
        for act in actions:
            act = act.strip()
            m = DEFINE_RE.match(act)
            if m and not in_def:
                in_def = True
                depth = 1
                cur_name = m.group(1)
                cur_start = i
                cur_buf = []

            if in_def:
                if IF_OPEN_RE.match(act) and not DEFINE_RE.match(act):
                    depth += 1
                elif END_RE.match(act):
                    depth -= 1

        if in_def:
            cur_buf.append(line)
            if depth == 0:
                text = "".join(cur_buf)
                tpl = Tpl(name=cur_name, start_line=cur_start, end_line=i, text=text)
                defines[cur_name] = tpl
                in_def = False
                cur_name = None
                cur_buf = []

    return defines

def analyze(defs: dict[str, Tpl]) -> None:
    for tpl in defs.values():
        tpl.includes = INCLUDE_RE.findall(tpl.text)
        tpl.input_reads = len(INPUT_RE.findall(tpl.text))
        tpl.outputs = len(OUT_C_RE.findall(tpl.text)) + len(OUT_S_RE.findall(tpl.text))

        # crude “loop guard” signal: if ne <cell> 0
        tpl.loop_guards = len(re.findall(r'\bif\s+ne\s+\$[A-Za-z0-9_]+\s+0\b', tpl.text))

        for act in ACTION_RE.findall(tpl.text):
            d = net_helm_delta(act)
            if d is not None and d != 0:
                tpl.helm_moves.append(d)

def emit_dot(defs: dict[str, Tpl]) -> str:
    out = ["digraph G {", '  node [shape=box, fontname="Consolas"];']
    for name, tpl in defs.items():
        label = f"{name}\\nL{tpl.start_line}-L{tpl.end_line}"
        if tpl.input_reads: label += f"\\n, x{tpl.input_reads}"
        if tpl.outputs: label += f"\\n. x{tpl.outputs}"
        if tpl.loop_guards: label += f"\\nloop? x{tpl.loop_guards}"
        out.append(f'  "{name}" [label="{label}"];')
        for callee in tpl.includes:
            out.append(f'  "{name}" -> "{callee}";')
    out.append("}")
    return "\n".join(out)

def emit_summary(defs: dict[str, Tpl]) -> str:
    names = sorted(defs.keys())
    lines = []
    for n in names:
        t = defs[n]
        inc = ", ".join(t.includes[:8]) + ("..." if len(t.includes) > 8 else "")
        mv = sum(t.helm_moves)
        lines.append(
            f"{n:24s}  L{t.start_line:5d}-L{t.end_line:5d}  "
            f"includes={len(t.includes):3d}  input={t.input_reads:2d}  out={t.outputs:2d}  "
            f"loop={t.loop_guards:2d}  helmMoves={len(t.helm_moves):3d} netHelm={mv:+d}  "
            f"[{inc}]"
        )
    return "\n".join(lines)

def main():
    if len(sys.argv) < 2:
        print("usage: python3 dehelm.py path/to/_helpers.tpl [--dot out.dot]")
        sys.exit(2)

    p = Path(sys.argv[1])
    defs = parse_defines(p)
    analyze(defs)

    if "--dot" in sys.argv:
        outp = Path(sys.argv[sys.argv.index("--dot") + 1])
        outp.write_text(emit_dot(defs), encoding="utf-8")
        print(f"Wrote dot: {outp}")

    print(emit_summary(defs))

if __name__ == "__main__":
    main()