import requests
import time
import base64
import json

# --- CẤU HÌNH ---
TOKEN = "MTQzNDE4ODc5MTgxNTM0NDEyOA.G3hM7w.p_XPNeQ598Otx8nx_6xDIFxYYU_jGcAf_lmimU"
GUILD_ID = "1431279362979664040"
# -----------------

# Thông tin cần thiết để gửi request
headers = {
    'Authorization': TOKEN
}
api_url = f"https://discord.com/api/v9/guilds/{GUILD_ID}/channels"

# Dùng dictionary để lưu các mảnh, key là ID kênh, value là tên kênh
# Dictionary sẽ tự động loại bỏ các mảnh bị trùng lặp
collected_channels = {}

print("Bắt đầu quét nhanh các kênh...")
# Quét 100 lần trong khoảng 20 giây (có thể điều chỉnh)
for i in range(100):
    try:
        # Gửi yêu cầu đến API
        response = requests.get(api_url, headers=headers)
        
        # Nếu yêu cầu thành công
        if response.status_code == 200:
            channels = response.json()
            # Tìm kênh có topic là '===='
            for channel in channels:
                if channel.get('topic') == '====':
                    # Lưu ID và tên kênh
                    channel_id = int(channel['id'])
                    channel_name = channel['name']
                    collected_channels[channel_id] = channel_name
                    break # Đã tìm thấy, thoát vòng lặp
            
            # In ra tiến trình
            print(f"\rĐã quét {i+1}/100 lần. Thu thập được {len(collected_channels)} mảnh duy nhất.", end="")
        else:
            print(f"\nLỗi khi gọi API: {response.status_code} - {response.text}")
            # Nếu bị rate limit, chờ một chút
            if response.status_code == 429:
                retry_after = response.json().get('retry_after', 1)
                print(f"Bị rate limit, đang chờ {retry_after} giây...")
                time.sleep(retry_after)

    except Exception as e:
        print(f"\nMột lỗi đã xảy ra: {e}")
    
    time.sleep(0.2) # Chờ một chút giữa các lần quét

print("\n\nQuét hoàn tất. Đang xử lý kết quả...")

if not collected_channels:
    print("Không thu thập được mảnh nào. Vui lòng kiểm tra lại Token và Server ID.")
else:
    # Sắp xếp các mảnh theo ID kênh (từ nhỏ đến lớn)
    sorted_channels = sorted(collected_channels.items())
    
    # Ghép tên các kênh lại
    full_base32_string = "".join([name for cid, name in sorted_channels])
    
    print(f"\nChuỗi Base32 đầy đủ đã ghép: {full_base32_string}")
    
    try:
        # Base32 yêu cầu padding đúng
        missing_padding = len(full_base32_string) % 8
        if missing_padding != 0:
            full_base32_string += '=' * (8 - missing_padding)
            
        # Giải mã
        decoded_flag = base64.b32decode(full_base32_string).decode('utf-8')
        print(f"\nFLAG: {decoded_flag}")
    except Exception as e:
        print(f"\nLỗi khi giải mã Base32: {e}")
        print("Có thể chuỗi thu thập được chưa hoàn chỉnh. Hãy thử chạy lại script.")