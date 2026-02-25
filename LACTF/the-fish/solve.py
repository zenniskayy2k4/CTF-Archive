import sys

TARGET = 996566347683429688961961964301023586804079510954147876054559647395459973491017596401595804524870382825132807985366740968983080828765835881807124832265927076916036640789039576345929756821059163439816195513160010797349073195590419779437823883987351911858848638715543148499560927646402894094060736432364692585851367946688748713386570173685483800217158511326927462877856683551550570195482724733002494766595319158951960049962201021071499099433062723722295346927562274516673373002429521459396451578444698733546474629616763677756873373867426542764435331574187942918914671163374771769499428478956051633984434410838284545788689925768605629646947266017951214152725326967051673704710610619169658404581055569343649552237459405389619878622595233883088117550243589990766295123312113223283666311520867475139053092710762637855713671921562262375388239616545168599659887895366565464743090393090917526710854631822434014024

def solve():
    print("[-] Đang bắt đầu giải mã...")
    current = TARGET
    path = []

    # 1. Giai đoạn hồi quy (Backtracking)
    # Thuật toán của Fisherator thêm một bit vào vị trí (len - 2) ở mỗi bước biến đổi.
    # Ta sẽ đảo ngược quá trình này bằng cách trừ đi giá trị đó.
    while current > 1:
        bit_len = current.bit_length()
        # Vị trí bit được thêm vào là length - 2
        k = bit_len - 2
        
        # Giá trị cần trừ để quay lại trạng thái trước
        val_to_remove = 1 << k
        
        prev = current - val_to_remove
        
        # Kiểm tra tính hợp lệ
        if prev <= 0:
            print(f"Lỗi: Giá trị âm tại current={current}")
            break

        prev_len = prev.bit_length()
        
        # Xác định xem bước này tương ứng với phép biến đổi nào trong Collatz
        if prev_len < bit_len:
            # Nếu độ dài bit giảm, nghĩa là bit cao nhất đã thay đổi
            # Đây tương ứng với bước "Even" (nhân 2 trong quá trình xuôi)
            path.append("E")
        else:
            # Nếu độ dài bit giữ nguyên (chỉ thay đổi các bit bên trong)
            # Đây tương ứng với bước "Odd" (3n+1 trong quá trình xuôi)
            path.append("O")
        
        current = prev

    print(f"[-] Đã tìm thấy {len(path)} bước biến đổi.")

    # 2. Giai đoạn tái tạo (Reconstruction)
    # Bắt đầu từ số 1 (điểm kết thúc của Collatz) và đi ngược lại đường dẫn đã tìm được
    n = 1
    for op in reversed(path):
        if op == "E":
            # Bước ngược của chia 2 là nhân 2
            n = n * 2
        else:
            # Bước ngược của 3n+1 là (n-1)/3
            # Kiểm tra xem có chia hết không (để đảm bảo tính đúng đắn)
            if (n - 1) % 3 != 0:
                print("Lỗi: Không chia hết cho 3 trong quá trình tái tạo.")
                break
            n = (n - 1) // 3

    # 3. Chuyển đổi số nguyên thành chuỗi (Flag)
    try:
        # Tính số byte cần thiết để chứa số n
        byte_len = (n.bit_length() + 7) // 8
        
        # Chuyển số n thành bytes (Big Endian)
        flag_bytes = n.to_bytes(byte_len, 'big')
        
        print(f"\n[+] Flag tìm được:\n{flag_bytes.decode('utf-8')}")
    except Exception as e:
        print(f"Lỗi khi chuyển đổi sang chuỗi: {e}")

if __name__ == "__main__":
    solve()