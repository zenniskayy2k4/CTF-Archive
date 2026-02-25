import sys

# Dữ liệu từ Binary (giữ nguyên để parse)
DATA = """
  *(undefined4 *)(this + 0x18) = 1;
  *(undefined4 *)(this + 0x3c) = 1;
  *(undefined4 *)(this + 0x40) = 2;
  *(undefined4 *)(this + 100) = 2;
  *(undefined4 *)(this + 0x68) = 4;
  *(undefined4 *)(this + 0x6c) = 5;
  *(undefined4 *)(this + 0x70) = 3;
  *(undefined4 *)(this + 0x78) = 6;
  *(undefined4 *)(this + 0x7c) = 3;
  *(undefined4 *)(this + 0x80) = 3;
  *(undefined4 *)(this + 0x88) = 4;
  *(undefined4 *)(this + 0x94) = 6;
  *(undefined4 *)(this + 0xac) = 4;
  *(undefined4 *)(this + 0xb0) = 5;
  *(undefined4 *)(this + 0xb8) = 5;
  *(undefined4 *)(this + 0xbc) = 6;
  *(undefined4 *)(this + 0xd4) = 5;
  *(undefined4 *)(this + 0xe0) = 7;
  *(undefined4 *)(this + 0x104) = 10;
  *(undefined4 *)(this + 0x108) = 10;
  *(undefined4 *)(this + 0x10c) = 7;
  *(undefined4 *)(this + 0x110) = 8;
  *(undefined4 *)(this + 0x118) = 4;
  *(undefined4 *)(this + 0x11c) = 0xb;
  *(undefined4 *)(this + 0x120) = 9;
  *(undefined4 *)(this + 0x134) = 0xb;
  *(undefined4 *)(this + 0x144) = 10;
  *(undefined4 *)(this + 0x168) = 6;
  *(undefined4 *)(this + 0x16c) = 0xc;
  *(undefined4 *)(this + 0x170) = 0xb;
  *(undefined4 *)(this + 0x178) = 0xc;
  *(undefined4 *)(this + 0x194) = 0xb;
  *(undefined4 *)(this + 0x19c) = 0xd;
  *(undefined4 *)(this + 0x1c0) = 0x10;
  *(undefined4 *)(this + 0x1c4) = 0xe;
  *(undefined4 *)(this + 0x1e8) = 0xf;
  *(undefined4 *)(this + 0x20c) = 0x10;
  *(undefined4 *)(this + 0x230) = 0x11;
  *(undefined4 *)(this + 0x238) = 0x13;
  *(undefined4 *)(this + 0x23c) = 0x13;
  *(undefined4 *)(this + 0x240) = 0x12;
  *(undefined4 *)(this + 0x254) = 0xd;
  *(undefined4 *)(this + 0x264) = 0x15;
  *(undefined4 *)(this + 0x268) = 0x15;
  *(undefined4 *)(this + 0x26c) = 0x13;
  *(undefined4 *)(this + 0x290) = 0x14;
  *(undefined4 *)(this + 0x298) = 0x15;
  *(undefined4 *)(this + 0x2b4) = 0x16;
  *(undefined4 *)(this + 700) = 0x15;
  *(undefined4 *)(this + 0x2c0) = 0x15;
  *(undefined4 *)(this + 0x2c4) = 0x11;
  *(undefined4 *)(this + 0x2c8) = 0x15;
  *(undefined4 *)(this + 0x2cc) = 0x16;
  *(undefined4 *)(this + 0x2f0) = 0x17;
  *(undefined4 *)(this + 0x2f8) = 0x19;
  *(undefined4 *)(this + 0x2fc) = 0x18;
  *(undefined4 *)(this + 0x314) = 0x19;
  *(undefined4 *)(this + 800) = 0x19;
  *(undefined4 *)(this + 0x344) = 0x1a;
  *(undefined4 *)(this + 0x368) = 0x1c;
  *(undefined4 *)(this + 0x36c) = 0x1b;
  *(undefined4 *)(this + 0x390) = 0x1c;
  *(undefined4 *)(this + 0x398) = 0x1d;
  *(undefined4 *)(this + 0x3b4) = 0x1c;
  *(undefined4 *)(this + 0x3bc) = 0x1e;
  *(undefined4 *)(this + 0x3e0) = 0x1a;
  *(undefined4 *)(this + 0x3e4) = 0x1e;
  *(undefined4 *)(this + 1000) = 0x1a;
  *(undefined4 *)(this + 0x3ec) = 0x1f;
  *(undefined4 *)(this + 0x410) = 0x20;
  *(undefined4 *)(this + 0x418) = 0x21;
  *(undefined4 *)(this + 0x434) = 0x20;
  *(undefined4 *)(this + 0x43c) = 0x23;
  *(undefined4 *)(this + 0x440) = 0x22;
  *(undefined4 *)(this + 0x464) = 0x24;
  *(undefined4 *)(this + 0x468) = 0x25;
  *(undefined4 *)(this + 0x46c) = 0x23;
  *(undefined4 *)(this + 0x490) = 0x24;
  *(undefined4 *)(this + 0x498) = 0x25;
  *(undefined4 *)(this + 0x4b4) = 0x24;
  *(undefined4 *)(this + 0x4bc) = 0x26;
  *(undefined4 *)(this + 0x4e0) = 0x27;
  *(undefined4 *)(this + 0x504) = 0x28;
  *(undefined4 *)(this + 0x528) = 0x29;
  *(undefined4 *)(this + 0x54c) = 0x29;
  *(undefined4 *)(this + 0x550) = 0x2a;
  *(undefined4 *)(this + 0x558) = 0x2b;
  *(undefined4 *)(this + 0x574) = 0x2d;
  *(undefined4 *)(this + 0x57c) = 0x2d;
  *(undefined4 *)(this + 0x580) = 0x2b;
  *(undefined4 *)(this + 0x584) = 0x2e;
  *(undefined4 *)(this + 0x588) = 0x2b;
  *(undefined4 *)(this + 0x58c) = 0x2c;
  *(undefined4 *)(this + 0x5b0) = 0x2d;
  *(undefined4 *)(this + 0x5b8) = 0x2f;
  *(undefined4 *)(this + 0x5bc) = 0x29;
  *(undefined4 *)(this + 0x5c0) = 0x2e;
  *(undefined4 *)(this + 0x5d4) = 0x29;
  *(undefined4 *)(this + 0x5e4) = 0x2f;
  *(undefined4 *)(this + 0x608) = 0x31;
  *(undefined4 *)(this + 0x60c) = 0x30;
  *(undefined4 *)(this + 0x630) = 0x31;
  *(undefined4 *)(this + 0x638) = 0x32;
  *(undefined4 *)(this + 0x654) = 0x34;
  *(undefined4 *)(this + 0x65c) = 0x33;
  *(undefined4 *)(this + 0x680) = 0x34;
  *(undefined4 *)(this + 0x6a4) = 0x35;
  *(undefined4 *)(this + 0x6c8) = 0x37;
  *(undefined4 *)(this + 0x6cc) = 0x36;
  *(undefined4 *)(this + 0x6f0) = 0x37;
  *(undefined4 *)(this + 0x6f8) = 0x3a;
  *(undefined4 *)(this + 0x6fc) = 0x38;
  *(undefined4 *)(this + 0x714) = 0x39;
  *(undefined4 *)(this + 0x720) = 0x39;
  *(undefined4 *)(this + 0x744) = 0x3a;
  *(undefined4 *)(this + 0x768) = 0x3c;
  *(undefined4 *)(this + 0x76c) = 0x3b;
  *(undefined4 *)(this + 0x790) = 0x3c;
  *(undefined4 *)(this + 0x798) = 0x3d;
  *(undefined4 *)(this + 0x7b4) = 0x3c;
  *(undefined4 *)(this + 0x7bc) = 0x3e;
  *(undefined4 *)(this + 0x7e0) = 0x3f;
  *(undefined4 *)(this + 0x804) = 0x42;
  *(undefined4 *)(this + 0x808) = 0x42;
  *(undefined4 *)(this + 0x80c) = 0x40;
  *(undefined4 *)(this + 0x830) = 0x41;
  *(undefined4 *)(this + 0x838) = 0x42;
  *(undefined4 *)(this + 0x854) = 0x44;
  *(undefined4 *)(this + 0x85c) = 0x43;
  *(undefined4 *)(this + 0x880) = 0x44;
  *(undefined4 *)(this + 0x8a4) = 0x45;
  *(undefined4 *)(this + 0x8c8) = 0x46;
  *(undefined4 *)(this + 0x8ec) = 0x42;
  *(undefined4 *)(this + 0x8f0) = 0x47;
  *(undefined4 *)(this + 0x8f8) = 0x49;
  *(undefined4 *)(this + 0x8fc) = 0x4a;
  *(undefined4 *)(this + 0x900) = 0x48;
  *(undefined4 *)(this + 0x914) = 0x43;
  *(undefined4 *)(this + 0x924) = 0x4a;
  *(undefined4 *)(this + 0x928) = 0x49;
  *(undefined4 *)(this + 0x94c) = 0x4a;
  *(undefined4 *)(this + 0x970) = 0x4b;
  *(undefined4 *)(this + 0x978) = 0x4c;
  *(undefined4 *)(this + 0x994) = 0x4b;
  *(undefined4 *)(this + 0x99c) = 0x4d;
  *(undefined4 *)(this + 0x9c0) = 0x4e;
  *(undefined4 *)(this + 0x9e4) = 0x4f;
  *(undefined4 *)(this + 0xa08) = 0x52;
  *(undefined4 *)(this + 0xa0c) = 0x50;
  *(undefined4 *)(this + 0xa30) = 0x51;
  *(undefined4 *)(this + 0xa38) = 0x52;
  *(undefined4 *)(this + 0xa54) = 0x51;
  *(undefined4 *)(this + 0xa5c) = 0x53;
  *(undefined4 *)(this + 0xa80) = 0x54;
  *(undefined4 *)(this + 0xaa4) = 0x55;
  *(undefined4 *)(this + 0xac8) = 0x56;
  *(undefined4 *)(this + 0xaec) = 0x58;
  *(undefined4 *)(this + 0xaf0) = 0x57;
  *(undefined4 *)(this + 0xaf8) = 0x59;
  *(undefined4 *)(this + 0xafc) = 0x57;
  *(undefined4 *)(this + 0xb00) = 0x58;
  *(undefined4 *)(this + 0xb14) = 0x53;
  *(undefined4 *)(this + 0xb24) = 0x5b;
  *(undefined4 *)(this + 0xb28) = 0x59;
  *(undefined4 *)(this + 0xb4c) = 0x5a;
  *(undefined4 *)(this + 0xb70) = 0x5b;
  *(undefined4 *)(this + 0xb78) = 0x5e;
  *(undefined4 *)(this + 0xb7c) = 0x57;
  *(undefined4 *)(this + 0xb80) = 0x57;
  *(undefined4 *)(this + 0xb84) = 0x5c;
  *(undefined4 *)(this + 0xb94) = 0x5d;
  *(undefined4 *)(this + 0xba8) = 0x58;
  *(undefined4 *)(this + 0xbac) = 0x5d;
  *(undefined4 *)(this + 0xbd0) = 0x5e;
  *(undefined4 *)(this + 0xbd8) = 0x5f;
  *(undefined4 *)(this + 0xbf4) = 0x61;
  *(undefined4 *)(this + 0xbfc) = 0x61;
  *(undefined4 *)(this + 0xc00) = 0x60;
  *(undefined4 *)(this + 0xc24) = 99;
  *(undefined4 *)(this + 0xc28) = 99;
  *(undefined4 *)(this + 0xc2c) = 0x61;
  *(undefined4 *)(this + 0xc50) = 0x62;
  *(undefined4 *)(this + 0xc58) = 99;
  *(undefined4 *)(this + 0xc74) = 100;
  *(undefined4 *)(this + 0xc7c) = 100;
  *(undefined4 *)(this + 0xca0) = 0x65;
  *(undefined4 *)(this + 0xcc4) = 0x66;
  *(undefined4 *)(this + 0xce8) = 0x67;
  *(undefined4 *)(this + 0xd0c) = 99;
  *(undefined4 *)(this + 0xd10) = 0x68;
  *(undefined4 *)(this + 0xd18) = 0x6a;
  *(undefined4 *)(this + 0xd1c) = 0x69;
  *(undefined4 *)(this + 0xd34) = 100;
  *(undefined4 *)(this + 0xd40) = 0x6c;
  *(undefined4 *)(this + 0xd44) = 0x6c;
  *(undefined4 *)(this + 0xd48) = 0x65;
  *(undefined4 *)(this + 0xd4c) = 0x6a;
  *(undefined4 *)(this + 0xd70) = 0x6b;
  *(undefined4 *)(this + 0xd78) = 0x6c;
  *(undefined4 *)(this + 0xd94) = 0x6b;
  *(undefined4 *)(this + 0xd9c) = 0x6d;
  *(undefined4 *)(this + 0xdc0) = 0x6d;
  *(undefined4 *)(this + 0xdc4) = 0x6d;
  *(undefined4 *)(this + 0xdc8) = 0x6e;
  *(undefined4 *)(this + 0xdec) = 0x6f;
  *(undefined4 *)(this + 0xdf8) = 0x6b;
  *(undefined4 *)(this + 0xdfc) = 0x6f;
  *(undefined4 *)(this + 0xe00) = 0x70;
  *(undefined4 *)(this + 0xe10) = 0x72;
  *(undefined4 *)(this + 0xe14) = 0x72;
  *(undefined4 *)(this + 0xe24) = 0x6c;
  *(undefined4 *)(this + 0xe28) = 0x71;
  *(undefined4 *)(this + 0xe4c) = 0x72;
  *(undefined4 *)(this + 0xe58) = 0x74;
  *(undefined4 *)(this + 0xe5c) = 0x72;
  *(undefined4 *)(this + 0xe60) = 0x73;
  *(undefined4 *)(this + 0xe70) = 0x6e;
  *(undefined4 *)(this + 0xe74) = 0x6e;
  *(undefined4 *)(this + 0xe84) = 0x73;
  *(undefined4 *)(this + 0xe88) = 0x74;
  *(undefined4 *)(this + 0xeac) = 0x75;
  *(undefined4 *)(this + 0xed0) = 0x76;
  *(undefined4 *)(this + 0xed8) = 0x77;
  *(undefined4 *)(this + 0xef4) = 0x78;
  *(undefined4 *)(this + 0xefc) = 0x78;
  *(undefined4 *)(this + 0xf20) = 0x79;
  *(undefined4 *)(this + 0xf44) = 0x7a;
  *(undefined4 *)(this + 0xf68) = 0x7b;
  *(undefined4 *)(this + 0xf8c) = 0x7d;
  *(undefined4 *)(this + 0xf90) = 0x7c;
  *(undefined4 *)(this + 0xf98) = 0x7d;
  *(undefined4 *)(this + 0xfb4) = 0x7c;
  *(undefined4 *)(this + 0xfbc) = 0x7e;
  *(undefined4 *)(this + 0xfe0) = 0x7f;
  *(undefined4 *)(this + 0x1004) = 0x80;
  *(undefined4 *)(this + 0x1028) = 0x82;
  *(undefined4 *)(this + 0x102c) = 0x81;
  *(undefined4 *)(this + 0x1050) = 0x82;
  *(undefined4 *)(this + 0x1058) = 0x85;
  *(undefined4 *)(this + 0x105c) = 0x83;
  *(undefined4 *)(this + 0x1074) = 0x7e;
  *(undefined4 *)(this + 0x1080) = 0x84;
  *(undefined4 *)(this + 0x10a4) = 0x80;
  *(undefined4 *)(this + 0x10a8) = 0x84;
  *(undefined4 *)(this + 0x10ac) = 0x85;
  *(undefined4 *)(this + 0x10d0) = 0x86;
  *(undefined4 *)(this + 0x10d8) = 0x87;
  *(undefined4 *)(this + 0x10f4) = 0x88;
  *(undefined4 *)(this + 0x10fc) = 0x88;
  *(undefined4 *)(this + 0x1120) = 0x89;
  *(undefined4 *)(this + 0x1144) = 0x8a;
  *(undefined4 *)(this + 0x1168) = 0x8b;
  *(undefined4 *)(this + 0x118c) = 0x8e;
  *(undefined4 *)(this + 0x1190) = 0x8c;
  *(undefined4 *)(this + 0x1198) = 0x8e;
  *(undefined4 *)(this + 0x119c) = 0x8f;
  *(undefined4 *)(this + 0x11a0) = 0x8d;
  *(undefined4 *)(this + 0x11b4) = 0x8c;
  *(undefined4 *)(this + 0x11c4) = 0x90;
  *(undefined4 *)(this + 0x11c8) = 0x8e;
  *(undefined4 *)(this + 0x11ec) = 0x8f;
  *(undefined4 *)(this + 0x1210) = 0x90;
  *(undefined4 *)(this + 0x1218) = 0x93;
  *(undefined4 *)(this + 0x121c) = 0x90;
  *(undefined4 *)(this + 0x1220) = 0x92;
  *(undefined4 *)(this + 0x1224) = 0x91;
  *(undefined4 *)(this + 0x1234) = 0x92;
  *(undefined4 *)(this + 0x1248) = 0x8d;
  *(undefined4 *)(this + 0x124c) = 0x92;
  *(undefined4 *)(this + 0x1270) = 0x93;
  *(undefined4 *)(this + 0x1278) = 0x94;
  *(undefined4 *)(this + 0x1294) = 0x93;
  *(undefined4 *)(this + 0x129c) = 0x94;
  *(undefined4 *)(this + 0x12a0) = 0x95;
  *(undefined4 *)(this + 0x12c4) = 0x97;
  *(undefined4 *)(this + 0x12c8) = 0x97;
  *(undefined4 *)(this + 0x12cc) = 0x96;
  *(undefined4 *)(this + 0x12f0) = 0x97;
  *(undefined4 *)(this + 0x12f8) = 0x98;
  *(undefined4 *)(this + 0x1314) = 0x9a;
  *(undefined4 *)(this + 0x131c) = 0x99;
  *(undefined4 *)(this + 0x1340) = 0x9a;
  *(undefined4 *)(this + 0x1364) = 0x9b;
  *(undefined4 *)(this + 5000) = 0x9c;
  *(undefined4 *)(this + 0x13ac) = 0x9c;
  *(undefined4 *)(this + 0x13b0) = 0x9d;
  *(undefined4 *)(this + 0x13b8) = 0x9d;
  *(undefined4 *)(this + 0x13bc) = 0x9e;
  *(undefined4 *)(this + 0x13d4) = 0xa0;
  *(undefined4 *)(this + 0x13e0) = 0x9f;
  *(undefined4 *)(this + 0x1404) = 0x9f;
  *(undefined4 *)(this + 0x1408) = 0x9b;
  *(undefined4 *)(this + 0x140c) = 0xa0;
  *(undefined4 *)(this + 0x1430) = 0xa1;
  *(undefined4 *)(this + 0x1438) = 0xa4;
  *(undefined4 *)(this + 0x143c) = 0xa4;
  *(undefined4 *)(this + 0x1440) = 0xa2;
  *(undefined4 *)(this + 0x1454) = 0xa1;
  *(undefined4 *)(this + 0x1464) = 0xa3;
  *(undefined4 *)(this + 0x1488) = 0x9f;
  *(undefined4 *)(this + 0x148c) = 0xa4;
  *(undefined4 *)(this + 0x14b0) = 0xa5;
  *(undefined4 *)(this + 0x14b8) = 0xa7;
  *(undefined4 *)(this + 0x14bc) = 0xa1;
  *(undefined4 *)(this + 0x14c0) = 0xa6;
  *(undefined4 *)(this + 0x14d4) = 0xa8;
  *(undefined4 *)(this + 0x14e4) = 0xa9;
  *(undefined4 *)(this + 0x14e8) = 0xa7;
  *(undefined4 *)(this + 0x150c) = 0xa8;
  *(undefined4 *)(this + 0x1518) = 0xa9;
  *(undefined4 *)(this + 0x1530) = 0xab;
  *(undefined4 *)(this + 0x1534) = 0xaa;
  *(undefined4 *)(this + 0x153c) = 0xaa;
  *(undefined4 *)(this + 0x1560) = 0xab;
  *(undefined4 *)(this + 0x1584) = 0x9f;
  *(undefined4 *)(this + 0x1584) = 0xa7;
  *(undefined4 *)(this + 0x1588) = 0xad;
  *(undefined4 *)(this + 0x158c) = 0xac;
  *(undefined4 *)(this + 0x15b0) = 0xad;
  *(undefined4 *)(this + 0x15b8) = 0xae;
  *(undefined4 *)(this + 0x15d4) = 0xa9;
  *(undefined4 *)(this + 0x15dc) = 0xaa;
  *(undefined4 *)(this + 0x15e0) = 0xae;
  *(undefined4 *)(this + 0x15e4) = 0xb1;
  *(undefined4 *)(this + 0x15e8) = 0xb1;
  *(undefined4 *)(this + 0x15ec) = 0xaf;
  *(undefined4 *)(this + 0x15f8) = 0xb0;
  *(undefined4 *)(this + 0x1610) = 0xaf;
  *(undefined4 *)(this + 0x1614) = 0xb1;
  *(undefined4 *)(this + 0x161c) = 0xb0;
  *(undefined4 *)(this + 0x1620) = 0xb1;
  *(undefined4 *)(this + 0x1644) = 0xb2;
  *(undefined4 *)(this + 0x1668) = 0xb3;
  *(undefined4 *)(this + 0x168c) = 0xb4;
  *(undefined4 *)(this + 0x16b0) = 0xb5;
  *(undefined4 *)(this + 0x16d4) = 0xb8;
"""

def fast_parse():
    adj = {}
    for line in DATA.splitlines():
        line = line.strip()
        if not line.startswith("*"): continue
        try:
            plus_idx = line.find("+")
            if plus_idx == -1: continue
            close_paren = line.find(")", plus_idx)
            offset_str = line[plus_idx+1 : close_paren].strip()
            eq_idx = line.find("=")
            semi_idx = line.find(";")
            value_str = line[eq_idx+1 : semi_idx].strip()
            
            offset = int(offset_str, 0)
            value = int(value_str, 0)
            
            if offset < 24: continue
            
            idx = (offset - 24) // 4
            state = idx // 8
            symbol = idx % 8
            next_state = value
            
            if state not in adj:
                adj[state] = []
            adj[state].append((symbol, next_state))
        except Exception:
            continue
    return adj

def solve_linear(graph):
    # Tìm đường đi tuyến tính: 0 -> 1 -> 2 -> ... -> 181
    path = []
    current_state = 0
    target_state = 181 # 0xb5
    
    while current_state < target_state:
        if current_state not in graph:
            print(f"[-] Stuck at state {current_state}")
            return None
        
        # Tìm symbol giúp nhảy sang state tiếp theo (current + 1)
        found_move = False
        for sym, nxt in graph[current_state]:
            if nxt == current_state + 1:
                path.append(sym)
                current_state = nxt
                found_move = True
                break
        
        if not found_move:
            print(f"[-] No transition from {current_state} to {current_state + 1}")
            return None
            
    return path

def pack(symbols):
    res = ""
    current_char = 0
    last_sym = -1
    
    for sym in symbols:
        if sym > last_sym:
            current_char |= (1 << sym)
            last_sym = sym
        else:
            res += chr(current_char)
            current_char = (1 << sym)
            last_sym = sym
    res += chr(current_char)
    return res

# --- MAIN ---
print("[*] Parsing data...")
g = fast_parse()

print("[*] Solving LINEAR path (0 -> 1 -> ... -> 181)...")
path = solve_linear(g)

if path:
    print(f"\n[+] SUCCESS! Path found with {len(path)} steps.")
    
    # Verify counts (Histogram check)
    from collections import Counter
    counts = Counter(path)
    target_counts = {
        0: 23, 1: 21, 2: 32, 3: 19, 
        4: 17, 5: 31, 6: 38, 7: 0
    }
    
    print("[*] Verifying Counts:")
    match = True
    for k in range(8):
        actual = counts.get(k, 0)
        target = target_counts[k]
        print(f"   Symbol {k}: Actual={actual}, Target={target} -> {'OK' if actual==target else 'FAIL'}")
        if actual != target: match = False
        
    if match:
        print("[+] HISTOGRAM MATCHED!")
        result = pack(path)
        
        # Vì kết quả có thể chứa ký tự không in được, ta nên ghi ra file
        print(result)
        
    else:
        print("[-] Path found but counts do not match target.")
else:
    print("[-] No path found.")