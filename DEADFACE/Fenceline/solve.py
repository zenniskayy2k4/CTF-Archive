def decrypt_rail_fence(ciphertext, key, offset=0):
    """
    Giải mã Rail Fence Cipher với key và offset cho trước.
    """
    if key <= 1:
        return ciphertext

    # Chiều dài của một chu kỳ zic-zắc hoàn chỉnh (xuống và lên)
    cycle_len = 2 * (key - 1)
    text_len = len(ciphertext)

    # --- Bước 1: Xác định vị trí bắt đầu và hướng đi dựa trên offset ---
    # Ta mô phỏng `offset` bước đi "ảo" để tìm ra rail và hướng đi bắt đầu
    current_rail = 0
    direction = 1  # 1 là đi xuống, -1 là đi lên
    for _ in range(offset):
        if current_rail == 0:
            direction = 1
        elif current_rail == key - 1:
            direction = -1
        current_rail += direction

    # --- Bước 2: Tính toán độ dài của mỗi hàng rào ---
    rail_lengths = [0] * key
    temp_rail = current_rail
    temp_dir = direction
    for _ in range(text_len):
        rail_lengths[temp_rail] += 1
        if temp_rail == 0:
            temp_dir = 1
        elif temp_rail == key - 1:
            temp_dir = -1
        temp_rail += temp_dir

    # --- Bước 3: Cắt chuỗi mã hóa thành các phần của mỗi hàng rào ---
    rails_text = []
    current_pos = 0
    for length in rail_lengths:
        rails_text.append(ciphertext[current_pos : current_pos + length])
        current_pos += length

    # --- Bước 4: Tái tạo lại văn bản gốc ---
    plaintext = ""
    rail_indices = [0] * key
    # Bắt đầu lại từ vị trí và hướng đi đã tính toán từ offset
    final_rail = current_rail
    final_dir = direction
    
    for _ in range(text_len):
        # Lấy ký tự từ đúng hàng rào
        plaintext += rails_text[final_rail][rail_indices[final_rail]]
        rail_indices[final_rail] += 1
        
        # Di chuyển đến hàng rào tiếp theo
        if final_rail == 0:
            final_dir = 1
        elif final_rail == key - 1:
            final_dir = -1
        final_rail += final_dir
        
    return plaintext

if __name__ == "__main__":
    ciphertext = "nattpader-ha-Ae{-wsnahD-!eHS-wtTak}ce-Uo--dna-spDHsgudfSl--eeukedtlad-emSainS-"
        
    # Thử các key từ 2 đến 20 (thường là đủ)
    for key in range(2, 21):
        # Offset chỉ cần thử trong một chu kỳ là đủ
        max_offset = 2 * (key - 1)
        for offset in range(max_offset):
            try:
                result = decrypt_rail_fence(ciphertext, key, offset)
                # In ra nếu kết quả có chứa deadface hoặc một phần có nghĩa
                if "deadface" in result or "the" in result.lower():
                    print(f"[*] Key: {key}, Offset: {offset} -> {result}")
            except IndexError:
                # Bỏ qua các trường hợp không hợp lệ
                continue