import re

def generate_interactive_html(filepath):
    print(f"[*] Đang trích xuất pixel từ: {filepath}...")
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Lỗi đọc file: {e}")
        return

    matches = re.findall(r'(6\.3937988|6\.3938293)', data)
    if not matches:
        print("[-] Không tìm thấy dữ liệu.")
        return

    print(f"[*] Thu hoạch được {len(matches)} pixel.")

    # Thử cả 2 trường hợp âm bản và dương bản
    bits_1 = [0 if '7988' in m else 1 for m in matches]
    bits_2 = [1 if '7988' in m else 0 for m in matches]

    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>CTF Binary Image Decoder</title>
        <style>
            body { background: #111; color: #0f0; font-family: monospace; text-align: center; }
            canvas { border: 1px solid #444; margin: 10px; image-rendering: pixelated; }
            input[type=range] { width: 80%; margin: 20px; cursor: pointer; }
            .val { font-size: 24px; color: #fff; font-weight: bold; }
        </style>
    </head>
    <body>
        <h2>Máy quét Hình ảnh Nhị phân</h2>
        <p>Kéo từ từ thanh trượt dưới đây cho đến khi các điểm ảnh lộn xộn xếp thành chữ!</p>
        
        <div>
            <label>Chiều ngang (Width): <span class="val" id="width_val">50</span> pixel</label><br>
            <input type="range" id="width_slider" min="10" max="300" value="50">
        </div>

        <div>
            <h3>Bản vẽ 1</h3>
            <canvas id="c1"></canvas>
        </div>
        <div>
            <h3>Bản vẽ 2 (Đảo màu)</h3>
            <canvas id="c2"></canvas>
        </div>

        <script>
            const bits1 = %s;
            const bits2 = %s;
            const total = bits1.length;
            const slider = document.getElementById('width_slider');
            const w_val = document.getElementById('width_val');
            const c1 = document.getElementById('c1');
            const c2 = document.getElementById('c2');

            function draw() {
                let w = parseInt(slider.value);
                let h = Math.ceil(total / w);
                w_val.innerText = w;
                
                // Set kích thước thật
                c1.width = w; c1.height = h;
                c2.width = w; c2.height = h;
                
                // Phóng to ảnh lên 5 lần để dễ nhìn chữ
                c1.style.width = (w * 5) + "px";
                c2.style.width = (w * 5) + "px";
                
                let ctx1 = c1.getContext('2d');
                let ctx2 = c2.getContext('2d');
                
                let img1 = ctx1.createImageData(w, h);
                let img2 = ctx2.createImageData(w, h);
                
                for(let i=0; i<total; i++) {
                    let val1 = bits1[i] ? 255 : 0; // Trắng hoặc Đen
                    let val2 = bits2[i] ? 255 : 0;
                    
                    let idx = i * 4;
                    // Kênh RGBA
                    img1.data[idx] = val1; img1.data[idx+1] = val1; img1.data[idx+2] = val1; img1.data[idx+3] = 255;
                    img2.data[idx] = val2; img2.data[idx+1] = val2; img2.data[idx+2] = val2; img2.data[idx+3] = 255;
                }
                ctx1.putImageData(img1, 0, 0);
                ctx2.putImageData(img2, 0, 0);
            }
            
            slider.oninput = draw;
            draw();
        </script>
    </body>
    </html>
    """ % (str(bits_1), str(bits_2))

    with open("decoder.html", "w", encoding="utf-8") as f:
        f.write(html)
    print("\n[+] XONG! Đã tạo công cụ tương tác: decoder.html")

if __name__ == "__main__":
    generate_interactive_html("uncompressed.pdf")