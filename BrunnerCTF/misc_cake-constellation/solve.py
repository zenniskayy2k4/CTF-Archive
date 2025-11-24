import matplotlib.pyplot as plt
from skyfield.api import load, EarthSatellite

def solve_constellation(tle_file_path):
    """
    Loads TLEs, calculates satellite ground tracks at specific times,
    and plots them to find the flag.
    """
    # Tải dữ liệu thời gian cần thiết
    ts = load.timescale()

    # Đọc và nạp các TLE từ file
    with open(tle_file_path, 'r') as f:
        lines = f.readlines()

    satellites = []
    # TLEs được định nghĩa theo bộ 3 dòng (Tên, Dòng 1, Dòng 2)
    for i in range(0, len(lines), 3):
        name = lines[i].strip()
        line1 = lines[i+1].strip()
        line2 = lines[i+2].strip()
        try:
            satellite = EarthSatellite(line1, line2, name, ts)
            satellites.append(satellite)
        except ValueError as e:
            print(f"Error loading TLE at line {i+1}: {e}")
            continue
    
    print(f"Loaded {len(satellites)} satellites.")

    # Lặp qua các giây từ 30 đến 39
    base_year, base_month, base_day = 2025, 8, 24
    base_hour, base_minute = 12, 26

    for second in range(30, 40):
        # Tạo đối tượng thời gian chính xác
        t = ts.utc(base_year, base_month, base_day, base_hour, base_minute, second)
        
        print(f"Calculating positions for {t.utc_iso()}...")

        longitudes = []
        latitudes = []

        # Tính toán vệt dưới mặt đất cho mỗi vệ tinh
        for sat in satellites:
            geocentric = sat.at(t)
            subpoint = geocentric.subpoint()
            latitudes.append(subpoint.latitude.degrees)
            longitudes.append(subpoint.longitude.degrees)

        # Vẽ biểu đồ
        plt.figure(figsize=(12, 6))
        plt.scatter(longitudes, latitudes, s=5, marker='.') # s là kích thước điểm, marker là hình dạng
        
        # Đảo ngược trục y để dễ đọc hơn (thường flag sẽ hiển thị đúng chiều)
        plt.gca().invert_yaxis()
        
        plt.title(f'Satellite Constellation at {t.utc_iso()}')
        plt.xlabel('Longitude (degrees)')
        plt.ylabel('Latitude (degrees)')
        plt.grid(True)
        
        # Lưu ảnh ra file
        filename = f'constellation_{second}.png'
        plt.savefig(filename)
        print(f"Saved plot to {filename}")
        plt.close()

# Chạy hàm giải
solve_constellation('TLEs.txt')