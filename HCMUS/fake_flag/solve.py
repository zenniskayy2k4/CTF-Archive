from Crypto.Util.number import long_to_bytes

# Các giá trị đã cho
p_val = 50969
q_val = 48859
r_val = 90254724465230431478307125031992674356849799682990984954478193657616557516363
k_val = 77613813229115705407983120551706296959236412766954020268752564135993144643307
d_val = 2111
number_val = 55082456475351903378255749118970454587034932966959264607612363109719848202778

FLAG_PREFIX = b"0160ca14{"
EXPECTED_FLAG_LEN = 35

# Bước 2: Tính k_inv
k_inv_mod_r = pow(k_val, -1, r_val)

# Bước 3: Tính T_mod_r
# T = (a-k)/d
# number = (k * T) % r  => T % r = (number * k_inv) % r
T_mod_r = (number_val * k_inv_mod_r) % r_val

# Bước 4: Tính a_base
# a = k + d * T
# a = k + d * (T_mod_r + m*r)
# a = (k + d * T_mod_r) + m * (d * r)
a_base = k_val + d_val * T_mod_r

# Bước 5: Tính modulus_for_m
modulus_for_m = d_val * r_val

# Bước 6: Lặp m
print(f"p = {p_val}")
print(f"q = {q_val}")
print(f"r = {r_val}")
print(f"k = {k_val}")
print(f"d = {d_val}")
print(f"number = {number_val}")
print(f"k_inv_mod_r = {k_inv_mod_r}")
print(f"T_mod_r = {T_mod_r}")
print(f"a_base = {a_base}")
print(f"modulus_for_m = {modulus_for_m}")

for m in range(2**100): # Thử một vài giá trị của m
    current_a = a_base + m * modulus_for_m
    
    # Đảm bảo current_a không âm nếu chẳng may a_base bị âm (không xảy ra ở đây)
    if current_a < 0:
        print(f"Skipping m={m} due to negative current_a")
        continue

    try:
        flag_bytes = long_to_bytes(current_a)
        # print(f"Trying m={m}, a={current_a}, bytes={flag_bytes[:len(FLAG_PREFIX)+5]}") # Debug print
        
        if flag_bytes.startswith(FLAG_PREFIX) and flag_bytes.endswith(b"}") and len(flag_bytes) == EXPECTED_FLAG_LEN:
            print(f"\n[+] Found FLAG with m = {m}:")
            try:
                print(flag_bytes.decode('ascii'))
                break
            except UnicodeDecodeError:
                print(f"Could not decode flag_bytes: {flag_bytes}")
                
    except OverflowError:
        print(f"OverflowError for m={m}, current_a might be negative if converted incorrectly")
    except Exception as e:
        #print(f"Error for m={m}: {e}") # Sometimes long_to_bytes fails if a is too small to fill a byte, but not relevant here
        pass
else:
    print("\n[-] FLAG not found with m in range.")