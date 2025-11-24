import websocket
import json

URL = "ws://litctf.org:31775/ws"

def solve():
    """
    Kết nối tới WebSocket, nhận câu hỏi kèm đáp án bị rò rỉ,
    và gửi lại đáp án đó để nhận câu hỏi tiếp theo.
    """
    try:
        # Tạo kết nối WebSocket
        ws = websocket.create_connection(URL)
        print(f"[+] Đã kết nối tới {URL}")

        # 1. Bắt đầu quiz
        # Gửi một tin nhắn rỗng để kích hoạt server gửi câu hỏi đầu tiên
        ws.send("")
        print("\n[*] Bắt đầu quiz...")

        # Vòng lặp để trả lời các câu hỏi
        while True:
            # 2. Nhận dữ liệu từ server (bao gồm cả câu hỏi và đáp án)
            response = ws.recv()
            if not response:
                print("[-] Không nhận được phản hồi từ server.")
                break
            
            data = json.loads(response)
            question = data.get("question", "Không có câu hỏi")
            answers = data.get("answer", [])

            print(f"\nS -> C: Nhận được câu hỏi: '{question}'")

            # 4. Kiểm tra xem đã nhận được flag chưa
            if "LITCTF" in question:
                print("\n=====================================")
                print(f"[SUCCESS] Flag tìm thấy: {question}")
                print("=====================================")
                break
            
            # 3. Lấy đáp án bị rò rỉ và gửi lại
            if answers:
                answer_to_send = answers[0]
                print(f"C -> S: Gửi đáp án: '{answer_to_send}'")
                ws.send(answer_to_send)
            else:
                print("[-] Server không gửi đáp án. Dừng lại.")
                break

    except ConnectionRefusedError:
        print(f"[-] Kết nối bị từ chối. Vui lòng kiểm tra lại URL ({URL}).")
    except Exception as e:
        print(f"[!] Đã xảy ra lỗi: {e}")
    finally:
        # Đóng kết nối
        if 'ws' in locals() and ws.connected:
            ws.close()
            print("\n[*] Đã đóng kết nối.")

if __name__ == "__main__":
    solve()