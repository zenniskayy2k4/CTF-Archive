def giai_ma_dich_chuyen(van_ban_ma_hoa):
  """
  Giải mã văn bản bằng cách dịch chuyển mỗi ký tự TIẾN 7 BẬC trong bảng mã ASCII.
  """
  van_ban_giai_ma = ""
  for ky_tu in van_ban_ma_hoa:
    # Lấy mã ASCII của ký tự
    ma_ascii = ord(ky_tu)
    
    # Cộng thêm 7 để dịch chuyển
    ma_ascii_moi = ma_ascii + 7
    
    # Chuyển mã ASCII mới trở lại thành ký tự
    ky_tu_moi = chr(ma_ascii_moi)
    
    # Nối ký tự đã giải mã vào kết quả cuối cùng
    van_ban_giai_ma += ky_tu_moi
    
  return van_ban_giai_ma

# --- Các chuỗi văn bản được lấy từ file HTML ---
chuoi_ma_hoa_1 = "BgbmbZmbg`l^"
chuoi_ma_hoa_2 = "k^mkZglfbllbhg'''"
chuoi_ma_hoa_3 = ">kkhk: AMMILMkZglfbllbhg_Zbenk^"
chuoi_ma_hoa_4 = "<Zimnk^]iZrehZ]3 FwMDAHgUUCSgL604vwkTvC0ch0nf7zvFgqmQnz9VZQ6dX5+XxLwsyGxR4oEdNFptaeNHuvThLSM6SgkHS8EmuWtu01yMyidUzcXUhY8muCcHbDFQrTtvzZgV2GMwN9oIwMv6Tc7mkbRfUhgrzDcZwJxrikMXDoICP5JjXB8="

print("=== Giải mã các chuỗi văn bản từ file HTML ===")
print("\nChuỗi 1 (đã giải mã):")
print(giai_ma_dich_chuyen(chuoi_ma_hoa_1))
print("\nChuỗi 2 (đã giải mã):")
print(giai_ma_dich_chuyen(chuoi_ma_hoa_2))
print("\nChuỗi 3 (đã giải mã):")
print(giai_ma_dich_chuyen(chuoi_ma_hoa_3))
print("\nChuỗi 4 (đã giải mã):")
print(giai_ma_dich_chuyen(chuoi_ma_hoa_4))