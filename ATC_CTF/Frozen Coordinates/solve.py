# --- START OF FILE solve_final.py ---
def dms_to_decimal(degrees, minutes, seconds, direction):
    decimal = degrees + minutes / 60 + seconds / 3600
    if direction in ['S', 'W']:
        decimal = -decimal
    return decimal

def encode_geohash(latitude, longitude, precision=10):
    """
    Tự cài đặt thuật toán Geohash chuẩn (Standard)
    để không phụ thuộc vào thư viện bên ngoài.
    """
    __base32 = '0123456789bcdefghjkmnpqrstuvwxyz'
    lat_interval = (-90.0, 90.0)
    lon_interval = (-180.0, 180.0)
    geohash = []
    bits = [16, 8, 4, 2, 1]
    bit = 0
    ch = 0
    even = True
    
    while len(geohash) < precision:
        if even:
            mid = (lon_interval[0] + lon_interval[1]) / 2
            if longitude > mid:
                ch |= bits[bit]
                lon_interval = (mid, lon_interval[1])
            else:
                lon_interval = (lon_interval[0], mid)
        else:
            mid = (lat_interval[0] + lat_interval[1]) / 2
            if latitude > mid:
                ch |= bits[bit]
                lat_interval = (mid, lat_interval[1])
            else:
                lat_interval = (lat_interval[0], mid)
        
        even = not even
        if bit < 4:
            bit += 1
        else:
            geohash.append(__base32[ch])
            bit = 0
            ch = 0
            
    return ''.join(geohash)

# --- DỮ LIỆU ĐẦU VÀO ---
# Latitude: 46° 30' 45.2304" North
lat_deg = 46
lat_min = 30
lat_sec = 45.2304
lat_dir = 'N'

# Longitude: 84° 20' 5.2224" West
lon_deg = 84
lon_min = 20
lon_sec = 5.2224
lon_dir = 'W'

# --- XỬ LÝ ---
lat_val = dms_to_decimal(lat_deg, lat_min, lat_sec, lat_dir)
lon_val = dms_to_decimal(lon_deg, lon_min, lon_sec, lon_dir)

print(f"1. Decimal Lat: {lat_val}")
print(f"2. Decimal Lon: {lon_val}")

result = encode_geohash(lat_val, lon_val, precision=10)
print(f"3. Geohash chuẩn (10 ký tự): {result}")

print("\n--- CÁC KHẢ NĂNG FLAG ---")
print(f"Type 1: atcctf_{result}")
print(f"Type 2 (Upper): atcctf_{result.upper()}")