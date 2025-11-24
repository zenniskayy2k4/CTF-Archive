# Lấy lời bài hát làm key
lyrics_key = """21 år, drengesind
Brænder benzin af på H.C. Andersens Boulevard
En pige spø'r om et lift: "Hey, det er cool med mig"
Vi har sædet tilbage
Vinduet ned
Volumen op
Sommerluften ind
Mig og hende
Vi har det godt
Huden glinser
Damn, det er hot
Vi kører ud mod Bellevue
Og solnedgangen - sikke en syn
Og jeg har følt det før - Déjavu
Da hun smiler og spørger, om vi ikke skal tage tilbage til byen
Og ruderne dugger
På grund af de ting hun gør ved mig, når vi cruiser
Alting er smukt nu, ikke også?!
Jeg må skrige nu: "Natten er vores!"
Lad mig se dig gå frem og tilbage
Fra side til side
Lad mig se dig gå op og ned
Kom nu, bliv ved
Lad mig se lidt sved på din krop
Baby, lad være at stop'
Temperaturen stiger
For vi': Hot, hot, hot, hot, hot
Her for mange mennesker der danser, fester
Mig og hende, danser tættere
Bassen pumper
Mangler luft, jeg
Rører hendes læber, skrider videre
Sommernætter, hun tager med mig
Det er ligeså hot udenfor
Sveder, drypper
Varmen trykker
Hvor går vi hen?
Der er ikke det vi ikke kan, vi bader i et springvand
Vådt tøj - jeg kan mærke hendes krop
Det gør mig høj - det kan ikke blive mere hot
Vandet fordamper på vores hud
Svedige tanker, vi tager videre ud
I natten
Kigger på hinanden
Hjertet banker
Stopper op... Ingen andre
Jeg ved ikke hvor vi er, men det kun os nu
Der er kun os to
Natten er vores nu
Lad mig se dig gå frem og tilbage
Fra side til side
Lad mig se dig gå op og ned
Kom nu, bliv ved
Lad mig se lidt sved på din krop
Baby, lad være at stop'
Temperaturen stiger
For vi': Hot, hot, hot, hot, hot
Lad mig se dig gå frem og tilbage
Fra side til side
Lad mig se dig gå op og ned
Kom nu, bliv ved
Lad mig se lidt sved på din krop
Baby, lad være at stop'
Temperaturen stiger
For vi': Hot, hot, hot, hot, hot
Daaamn, det er så hot, lad mig se jer smide de hænder op
Bounce med os, jeg ved at I er hot
Bounce med os, jeg ved at I er hot
Vi ved du vil have mere
Det er lige meget hvem du er
For det er så hot det her
Hot, hot, hot, hot
Lad temperaturen stige i hele DK
Århus Odense og KBH
Mere at se på, flere piger uden tøj på
Vi er vilde i varmen
Shheeh - det er hot nu
Mere aircondition, flere drinks i skyggen
Flere piger der viser g-streng på cyklen
Der er hot i din bil, på din club og i din seng
Der er hot overalt så lad mig høre jeg synge:
Lad mig se dig gå frem og tilbage
Fra side til side
Lad mig se dig gå op og ned
Kom nu, bliv ved
Lad mig se lidt sved på din krop
Baby, lad være at stop'
Temperaturen stiger
For vi': Hot, hot, hot, hot, hot
Lad mig se dig gå frem og tilbage
Fra side til side
Lad mig se dig gå op og ned
Kom nu, bliv ved
Lad mig se lidt sved på din krop
Baby, lad være at stop'
Temperaturen stiger
For vi': Hot, hot, hot, hot, hot""".encode('utf-8') # Chuyển key thành bytes

# Đọc toàn bộ file binary gốc
try:
    with open('bake_and_forth', 'rb') as f:
        ciphertext = f.read()
except FileNotFoundError:
    print("Lỗi: Không tìm thấy file 'bake_and_forth'. Hãy đảm bảo file ở cùng thư mục với script.")
    exit()

# Tạo mảng byte để chứa kết quả giải mã
plaintext = bytearray(len(ciphertext))

# Thực hiện XOR
for i in range(len(ciphertext)):
    # Lấy byte từ ciphertext và key (key được lặp lại)
    cipher_byte = ciphertext[i]
    key_byte = lyrics_key[i % len(lyrics_key)]
    
    # XOR và lưu kết quả
    plaintext[i] = cipher_byte ^ key_byte

# Lưu kết quả ra file mới để phân tích
with open('completely_decrypted.bin', 'wb') as f:
    f.write(plaintext)

print("Đã giải mã file và lưu vào 'completely_decrypted.bin'")
print("Hãy thử tìm kiếm (grep) chuỗi 'HTB{' trong file này, hoặc mở nó bằng trình xem hex.")