from pwn import *
import json
import math
import random
import time

# ==========================================
# CẤU HÌNH
# ==========================================
HOST = 'challenge.cnsc.com.vn' 
PORT = 31662
context.log_level = 'critical' # Giảm log để chạy nhanh hơn

# ==========================================
# SIMULATION LOGIC (RUST PORT)
# ==========================================
FRAME_TIME = 0.0666

class Strategy:
    FRONT = 0; PACE = 1; LATE = 2; END = 3

def get_coeffs(strategy):
    if strategy == Strategy.FRONT:
        return {'speed': [1.0, 0.98, 0.962], 'accel': [1.0, 1.0, 0.996], 'hp': 0.95}
    elif strategy == Strategy.PACE:
        return {'speed': [0.978, 0.991, 0.975], 'accel': [0.985, 1.0, 0.996], 'hp': 0.89}
    elif strategy == Strategy.LATE:
        return {'speed': [0.938, 0.998, 0.994], 'accel': [0.975, 1.0, 1.0], 'hp': 1.0}
    return {'speed': [0.931, 1.0, 1.0], 'accel': [0.945, 1.0, 0.997], 'hp': 0.995}

class Horse:
    def __init__(self, name, stats, strategy_idx):
        self.name = name; self.stats = stats; self.strategy = strategy_idx
        wit = self.stats['wit']
        val = wit * 0.1
        log_val = math.log10(val) if val > 0 else 0
        self.random_fluctuation = (wit / 5500.0) * log_val

    def initialize_race(self, race_distance):
        coeffs = get_coeffs(self.strategy)
        self.max_hp = 0.8 * coeffs['hp'] * self.stats['stamina'] + race_distance
        self.current_hp = self.max_hp
        self.distance_covered = 0.0; self.current_speed = 3.0; self.finish_time = None
        self.phase = 0; self.is_spurt_active = False; self.out_of_hp = False; self.start_dash_active = True

    def update(self, dt, race_base_speed, race_distance):
        if self.finish_time is not None: return
        progress = self.distance_covered / race_distance
        if progress < 0.166: self.phase = 0
        elif progress < 0.666: self.phase = 1
        else: self.phase = 2

        coeffs = get_coeffs(self.strategy)
        coef_idx = 2 if self.phase >= 2 else self.phase
        target_speed = race_base_speed * coeffs['speed'][coef_idx]
        
        # Wiggle simulation
        wit_shift = min(self.stats['wit'] / 10000.0, 0.004)
        min_w = self.random_fluctuation - 0.0065 - wit_shift
        max_w = self.random_fluctuation + wit_shift
        wiggle = random.uniform(min_w, max_w)
        target_speed *= (1.0 + wiggle)

        if self.phase == 2:
            base_late_boost = math.sqrt(500.0 * self.stats['speed']) * 0.002
            target_speed += base_late_boost
            if not self.is_spurt_active and not self.out_of_hp:
                guts_factor = pow(450.0 * self.stats['guts'], 0.597) * 0.0001
                max_spurt_target = (target_speed + 0.01 * race_base_speed) * 1.05 + base_late_boost + guts_factor
                dist_remain = race_distance - self.distance_covered
                time_remain = dist_remain / max_spurt_target if max_spurt_target > 0 else 9999
                hp_cost_est = 20.0 * pow(max_spurt_target - race_base_speed + 12.0, 2) / 144.0
                guts_save = 1.0 + (200.0 / math.sqrt(600.0 * self.stats['guts']))
                if self.current_hp > hp_cost_est * guts_save * time_remain * 0.8:
                    self.is_spurt_active = True

            if self.is_spurt_active:
                guts_factor = pow(450.0 * self.stats['guts'], 0.597) * 0.0001
                target_speed = (target_speed + 0.01 * race_base_speed) * 1.05 + guts_factor
                self.phase = 3

        if self.current_hp <= 0.0:
            self.out_of_hp = True; self.current_hp = 0.0
            min_speed = 0.85 * race_base_speed + math.sqrt(200.0 * self.stats['guts']) * 0.001
            target_speed = min_speed

        base_accel = 0.0006
        if self.start_dash_active:
            if self.current_speed < 0.85 * race_base_speed and self.phase == 0: base_accel = 24.0
            else: self.start_dash_active = False
        
        accel = base_accel * math.sqrt(500.0 * self.stats['power']) * coeffs['accel'][coef_idx]
        if self.current_speed < target_speed:
            self.current_speed = min(self.current_speed + accel * dt, target_speed)
        else:
            decel = -1.2 if self.phase == 0 or self.out_of_hp else -0.8 if self.phase == 1 else -1.0
            self.current_speed = max(self.current_speed + decel * dt, target_speed)
            
        if self.current_speed > 30.0: self.current_speed = 30.0
        hp_consumption = 20.0 * pow(self.current_speed - race_base_speed + 12.0, 2) / 144.0
        if self.phase >= 2: hp_consumption *= (1.0 + (200.0 / math.sqrt(600.0 * self.stats['guts'])))
        self.current_hp -= hp_consumption * dt
        self.distance_covered += self.current_speed * dt

def run_simulation(entries, distance):
    horses = [Horse(e['name'], e, e['strategy_idx']) for e in entries]
    [h.initialize_race(distance) for h in horses]
    race_base = 20.0 - (distance - 2000.0) / 1000.0
    time_el = 0.0; finished = 0; total = len(horses); frames = 0
    while finished < total and frames < 15000:
        time_el += FRAME_TIME; frames += 1; finished = 0
        for h in horses:
            h.update(FRAME_TIME, race_base, distance)
            if h.distance_covered >= distance and h.finish_time is None: h.finish_time = time_el
            if h.finish_time: finished += 1
    res = [(i, h.finish_time or 99999.0) for i, h in enumerate(horses)]
    res.sort(key=lambda x: x[1])
    return res[0][0]

def predict_winner(entries, distance):
    # Chạy 100 lần Monte Carlo
    wins = {}
    for _ in range(100):
        w = run_simulation(entries, distance)
        wins[w] = wins.get(w, 0) + 1
    return sorted(wins.items(), key=lambda x: x[1], reverse=True)[0]

def parse_strategy(name):
    if "late" in name.lower(): return Strategy.LATE
    if "end" in name.lower(): return Strategy.END
    if "pace" in name.lower(): return Strategy.PACE
    return Strategy.FRONT

# ==========================================
# MAIN SOLVER
# ==========================================
def solve_round(p, round_num):
    # 1. Setup
    p.recvuntil(b'Register your horse name:')
    p.sendline(b'HackerHorse')
    p.recvuntil(b'Strategy selection:')
    p.sendline(b'3') # Late charge

    # 2. Parse Stats
    p.recvuntil(b'Race distance: ')
    dist = int(p.recvline().strip().replace(b'm', b''))
    p.recvuntil(b'Stats [spd sta pow gut wit]\n')
    entries = []
    user_slot = -1
    
    for i in range(16):
        line = p.recvline().decode().strip()
        # Regex parsing để fix lỗi *13
        parts = re.split(r'\s*\|\s*', line)
        idx_str = parts[0].strip()
        if '*' in idx_str: user_slot = int(idx_str.replace('*', ''))
        
        st = parts[3].replace('[', '').replace(']', '').split()
        entries.append({
            'name': parts[1], 'strategy_idx': parse_strategy(parts[2]),
            'speed': float(st[0]), 'stamina': float(st[1]), 'power': float(st[2]),
            'guts': float(st[3]), 'wit': float(st[4])
        })

    # 3. Predict
    p.recvuntil(b'Proof JSON (share & submit later):\n')
    payload = json.loads(p.recvline().decode())
    
    best_idx, win_count = predict_winner(entries, float(dist))
    sibling_idx = user_slot ^ 1
    
    print(f"[R{round_num}] Dist:{dist} Slot:{user_slot} | Pred:{best_idx} ({win_count}%)")

    # --- CHIẾN THUẬT REROLL ---
    # Nếu là Round 1 và tỉ lệ thắng thấp hoặc không phải phe mình thắng -> Bỏ ngay
    if round_num == 1:
        if (best_idx != user_slot and best_idx != sibling_idx) or win_count < 60:
            print(f"   -> BAD START. Rerolling...")
            return False # Disconnect
    
    # Ở Round 2+, không thể Reroll, buộc phải đánh
    final_payload = payload.copy()
    if best_idx == sibling_idx: # Sibling Exploit
        final_payload['index'] = sibling_idx
        final_payload['leaf'] = payload['path_elements'][0]
        final_payload['path_elements'][0] = payload['leaf']
        final_payload['path_indices'][0] = 1 - final_payload['path_indices'][0]
        print("   -> Using Sibling Proof")
    elif best_idx != user_slot:
        print("   -> Praying (Submitting my own proof against odds)")
    else:
        print("   -> Submitting my Proof")

    p.recvuntil(b'Submit your proof JSON:')
    p.sendline(json.dumps(final_payload).encode())
    
    res = p.recvline().decode()
    if "Victory" in res: return True
    if "Congrats" in res:
        print("\n" + p.recvall().decode()); exit(0)
    return False

def main():
    while True:
        try:
            p = remote(HOST, PORT, level='error')
            for r in range(1, 51):
                if not solve_round(p, r):
                    p.close()
                    break
            else:
                print("WINNER!")
                break
        except KeyboardInterrupt: break
        except: time.sleep(0.5)

if __name__ == "__main__":
    main()