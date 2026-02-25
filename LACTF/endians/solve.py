# Nội dung từ file chall.txt
content = "氀愀挀琀昀笀㄀开猀甀爀㌀开栀　瀀攀开琀栀㄀猀开搀　攀猀开渀　琀开最㌀琀开氀　猀琀开㄀渀开琀爀愀渀猀氀愀琀椀　渀℀紀"

# Đảo ngược quá trình endianness
# Mã hóa LE để lấy lại các cặp byte gốc, sau đó đọc lại theo BE
flag = content.encode('utf-16-le').decode('utf-16-be')

print(f"Flag là: {flag}")