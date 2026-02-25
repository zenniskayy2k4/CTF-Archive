import re
import zipfile
import io
import os
try:
    import fitz  # PyMuPDF
except ImportError:
    print("[-] Vui lòng cài đặt: pip install pymupdf")
    exit()

def uncrop_pdf(pdf_bytes, output_name):
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
        for page in doc:
            # Lấy thông số khung nhìn hiện tại
            rect = page.rect
            
            # Ép PDF "ăn nấm": Kéo dài chiều cao trang giấy xuống dưới thêm 1000 pixel
            rect.y1 += 1000  
            
            # Ghi đè khung nhìn mới
            page.set_mediabox(rect)
            page.set_cropbox(rect)
            
        doc.save(output_name)
        print(f"  -> Đã giải phóng giới hạn, lưu thành: {output_name}")
    except Exception as e:
        print(f"  [!] Bỏ qua file lỗi: {e}")

def solve():
    print("[+] Cho TẤT CẢ các file PDF ăn Nấm (Uncrop)...\n")
    try:
        with open('dubs.pdf', 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print("[-] Không tìm thấy file dubs.pdf")
        return

    out_dir = "uncropped_pdfs"
    os.makedirs(out_dir, exist_ok=True)
    
    layer = 1
    while data:
        print(f"--- ĐANG XỬ LÝ LỚP {layer} ---")
        
        # Cắt file thành các luồng PDF riêng biệt
        pdf_offsets = [m.start() for m in re.finditer(b'%PDF-', data)]
        zip_offset = data.find(b'PK\x03\x04')
        if zip_offset == -1: zip_offset = len(data)

        for i in range(len(pdf_offsets)):
            start = pdf_offsets[i]
            end = pdf_offsets[i+1] if i < len(pdf_offsets)-1 else zip_offset
            pdf_data = data[start:end]
            
            # Ép Uncrop và lưu vào thư mục
            out_name = os.path.join(out_dir, f"layer{layer}_pdf{i+1}_uncropped.pdf")
            uncrop_pdf(pdf_data, out_name)

        # Chui xuống lớp đệ quy qua file ZIP
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                names = z.namelist()
                if not names: break
                data = z.read(names[0])
                layer += 1
        except zipfile.BadZipFile:
            break

    print("\n[!] HOÀN TẤT! Hãy mở thư mục 'uncropped_pdfs'.")
    print("[!] Dùng Chrome hoặc trình đọc PDF mở từng file lên và CUỘN XUỐNG DƯỚI CÙNG.")
    print("[!] Các mảnh cờ được vẽ bằng đồ họa vector sẽ hiện nguyên hình!")

if __name__ == "__main__":
    solve()