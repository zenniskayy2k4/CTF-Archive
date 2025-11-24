#!/usr/bin/env python3
# solve_asis_svg.py
# Usage: python solve_asis_svg.py asis_led.svg.txt
# Attempts to reconstruct a netlist from a netlistsvg-generated SVG and simulate it
# for input string "ASIS". Tries multiple heuristics for pin/output detection.

import sys, re, math
from collections import defaultdict

if len(sys.argv) < 2:
    print("Usage: python solve_asis_svg.py asis_led.svg.txt")
    sys.exit(1)

svg_path = sys.argv[1]
svg = open(svg_path, 'r', encoding='utf-8').read()

# regex helpers
tag_re = re.compile(r'(<[^>]+>)')
attr_re = re.compile(r'([^\s=]+)\s*=\s*"([^"]*)"')
num_re = re.compile(r'[-+]?\d*\.?\d+')

# tokenize
tokens = []
pos = 0
for m in tag_re.finditer(svg):
    if m.start()>pos:
        tokens.append(("text", svg[pos:m.start()]))
    tokens.append(("tag", m.group(1)))
    pos = m.end()
if pos < len(svg):
    tokens.append(("text", svg[pos:]))

# collect basic elements and track group transforms and s:type
elements = []
group_stack = []
i = 0
while i < len(tokens):
    typ, content = tokens[i]
    if typ == "tag":
        tagtxt = content
        is_close = tagtxt.startswith("</")
        mtag = re.match(r'<\s*/?\s*([^\s>/]+)', tagtxt)
        tag = mtag.group(1) if mtag else None
        attrs = {a[0]:a[1] for a in attr_re.findall(tagtxt)}
        if (not is_close) and tag == 'g':
            gtype = attrs.get('s:type')
            transform = attrs.get('transform','')
            trans = (0.0, 0.0)
            mt = re.search(r'translate\(\s*([-\d.]+)(?:[ ,]+([-\d.]+))?', transform)
            if mt:
                tx=float(mt.group(1)); ty=float(mt.group(2)) if mt.group(2) else 0.0
                parent_trans = group_stack[-1]['trans'] if group_stack else (0.0,0.0)
                trans = (parent_trans[0]+tx, parent_trans[1]+ty)
            group_stack.append({'type':gtype,'attrs':attrs,'trans':trans})
        else:
            parent_trans = group_stack[-1]['trans'] if group_stack else (0.0,0.0)
            if tag == 'path':
                d = attrs.get('d','')
                nums = [float(n) for n in num_re.findall(d)]
                pts = [(nums[j]+parent_trans[0], nums[j+1]+parent_trans[1]) for j in range(0,len(nums)-1,2)] if nums else []
                elements.append({'etype':'path','pts':pts,'attrs':attrs,'parent':group_stack[-1] if group_stack else None})
            elif tag == 'line':
                x1=float(attrs.get('x1','0'))+parent_trans[0]; y1=float(attrs.get('y1','0'))+parent_trans[1]
                x2=float(attrs.get('x2','0'))+parent_trans[0]; y2=float(attrs.get('y2','0'))+parent_trans[1]
                elements.append({'etype':'line','pts':[(x1,y1),(x2,y2)],'attrs':attrs,'parent':group_stack[-1] if group_stack else None})
            elif tag == 'circle':
                cx=float(attrs.get('cx','0'))+parent_trans[0]; cy=float(attrs.get('cy','0'))+parent_trans[1]
                r=float(attrs.get('r','0'))
                elements.append({'etype':'circle','cx':cx,'cy':cy,'r':r,'attrs':attrs,'parent':group_stack[-1] if group_stack else None})
            elif tag == 'text':
                raw=''
                j = i+1
                while j < len(tokens):
                    if tokens[j][0]=='tag' and tokens[j][1].startswith("</text"): break
                    raw += tokens[j][1]
                    j+=1
                txt = raw.strip()
                x = float(attrs.get('x','0'))+parent_trans[0]; y=float(attrs.get('y','0'))+parent_trans[1]
                elements.append({'etype':'text','text':txt,'x':x,'y':y,'attrs':attrs,'parent':group_stack[-1] if group_stack else None})
        if is_close and tag=='g' and group_stack:
            group_stack.pop()
    i+=1

# anchors: endpoints of paths/lines, circle centers, xN/yN text coords
anchors = []
for e in elements:
    if e['etype'] in ('path','line'):
        pts = e.get('pts',[])
        if pts:
            anchors.append({'pt':pts[0],'elem':e})
            anchors.append({'pt':pts[-1],'elem':e})
    elif e['etype']=='circle':
        anchors.append({'pt':(e['cx'], e['cy']),'elem':e})
    elif e['etype']=='text':
        t = e['text'].strip()
        if re.match(r'^[xy]\d+$', t):
            anchors.append({'pt':(e['x'], e['y']),'elem':e,'label':t})

# cluster anchors into nets
def dist(a,b): return math.hypot(a[0]-b[0], a[1]-b[1])
threshold = 6.0
net_id = {}
nets = []
for idx,a in enumerate(anchors):
    if idx in net_id: continue
    nid=len(nets); nets.append([]); stack=[idx]; net_id[idx]=nid
    while stack:
        cur = stack.pop()
        nets[nid].append(anchors[cur])
        for j,b in enumerate(anchors):
            if j in net_id: continue
            if dist(anchors[cur]['pt'], b['pt']) <= threshold:
                net_id[j]=nid; stack.append(j)

# label->net
label_net = {}
for i,a in enumerate(anchors):
    if 'label' in a:
        label_net[a['label']] = net_id[i]

# parent groups (gates)
parent_groups = {}
for e in elements:
    p = e.get('parent')
    if p:
        pid = id(p)
        if pid not in parent_groups:
            parent_groups[pid] = {'group':p, 'elems':[]}
        parent_groups[pid]['elems'].append(e)

def build_gates_by_heuristic(pin_out='rightmost', gate_point_thresh=8.0):
    gates=[]
    for info in parent_groups.values():
        g = info['group']
        gtype = g.get('type')
        if not gtype: continue
        nets_touch=set()
        net_coords=defaultdict(list)
        for elem in info['elems']:
            pts=[]
            if elem['etype'] in ('path','line'):
                pts = elem.get('pts',[])
            elif elem['etype']=='circle':
                pts = [(elem['cx'], elem['cy'])]
            elif elem['etype']=='text':
                pts = [(elem['x'], elem['y'])]
            for p in pts:
                for i,a in enumerate(anchors):
                    if dist(p, a['pt']) <= gate_point_thresh:
                        nets_touch.add(net_id[i])
                        net_coords[net_id[i]].append(a['pt'])
        if not nets_touch: continue
        # representative coord per net
        net_rep = {nid:(sum(c[0] for c in net_coords[nid])/len(net_coords[nid]),
                       sum(c[1] for c in net_coords[nid])/len(net_coords[nid])) for nid in net_coords}
        # pick output by heuristic
        items = list(net_rep.items())
        if pin_out == 'rightmost':
            out_nid = max(items, key=lambda kv: kv[1][0])[0]
        elif pin_out == 'leftmost':
            out_nid = min(items, key=lambda kv: kv[1][0])[0]
        elif pin_out == 'middle_x':
            meanx = sum(v[0] for v in net_rep.values())/len(net_rep)
            out_nid = min(items, key=lambda kv: abs(kv[1][0]-meanx))[0]
        else:
            out_nid = max(items, key=lambda kv: kv[1][0])[0]
        in_nids = [nid for nid in net_rep.keys() if nid != out_nid]
        gates.append({'type':gtype,'out':out_nid,'ins':in_nids})
    return gates

# helper to eval gates
def eval_gate_func(g, netvals):
    t = g['type']; vals=[netvals.get(n, False) for n in g['ins']]
    if t == 'and': return all(vals) if vals else False
    if t in ('or','reduce_or'): return any(vals) if vals else False
    if t == 'not': return (not vals[0]) if vals else True
    if t in ('reduce_xor','xor'): 
        s=False
        for v in vals: s ^= bool(v)
        return s
    return False

# two bit-order conventions to try: LSB-first per byte, and MSB-first per byte
def bits_from_str(s, lsb_per_byte=True):
    bits=[]
    for ch in s:
        b = ord(ch)
        if lsb_per_byte:
            for i in range(8): bits.append((b>>i)&1)
        else:
            for i in range(8): bits.append((b>>(7-i))&1)
    return bits

input_nets = {int(k[1:]):v for k,v in label_net.items() if k.startswith('x')}
output_nets = {int(k[1:]):v for k,v in label_net.items() if k.startswith('y')}

def simulate(gates, input_bits):
    netvals = {}
    # set input nets
    for xi, nid in input_nets.items():
        netvals[nid] = bool(input_bits[xi]) if xi < len(input_bits) else False
    # iterate
    for _ in range(500):
        changed=False
        for g in gates:
            v = eval_gate_func(g, netvals)
            if netvals.get(g['out'], None) != v:
                netvals[g['out']] = v; changed=True
        if not changed: break
    # build output bytes
    outbits=[ 1 if netvals.get(output_nets[i], False) else 0 for i in range(32) ]
    # convert to 4 ASCII using bytes: pack 8 bits per char; try LSB-first per byte assumption
    def bits_to_chars(bits, lsb_per_byte=True):
        res=[]
        for i in range(0,32,8):
            byte_bits = bits[i:i+8]
            val = 0
            if lsb_per_byte:
                for j,b in enumerate(byte_bits): val |= (b&1) << j
            else:
                for j,b in enumerate(byte_bits): val |= (b&1) << (7-j)
            res.append(val)
        try:
            return ''.join(chr(v) for v in res), res
        except:
            return ''.join('\\x%02x'%v for v in res), res
    return outbits, bits_to_chars(outbits, lsb_per_byte=True), bits_to_chars(outbits, lsb_per_byte=False)

# try a few heuristics
heuristics = [
    ('rightmost', 6.0),
    ('rightmost', 8.0),
    ('leftmost', 6.0),
    ('leftmost', 8.0),
    ('middle_x', 8.0),
]
inputs = "ASIS"
for pin_out, thresh in heuristics:
    gates = build_gates_by_heuristic(pin_out=pin_out, gate_point_thresh=thresh)
    for lsb_conv in (True, False):
        bits = bits_from_str(inputs, lsb_per_byte=lsb_conv)
        outbits, out_lsb, out_msb = simulate(gates, bits)
        # out_lsb/out_msb returned as (string, byteslist) in simulate; but simulate returns nested; fix:
        outbits, out_lsb, out_msb = simulate(gates, bits)
        print("HEURISTIC:", pin_out, "thresh", thresh, "input bit-order LSB_per_byte?", lsb_conv)
        print("  out bits:","".join(str(b) for b in outbits))
        print("  ASCII (LSB per byte decode):", out_lsb[0], "raw bytes:", out_lsb[1])
        print("  ASCII (MSB per byte decode):", out_msb[0], "raw bytes:", out_msb[1])
        print("-"*60)

print("Done. If none look like readable English, try adjusting thresholds or inspect SVG visually to identify pin orientations.")
