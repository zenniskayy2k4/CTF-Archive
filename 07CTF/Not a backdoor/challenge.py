import os,json,base64,secrets
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from fastecdsa.curve import P256
from Crypto.Util.Padding import pad
from secret import FLAG

OUT_BYTES=30
OUT_MASK=(1<<(8*OUT_BYTES))-1
ROUNDS=6
D = 32

class CSPRNG:
    OUT_BYTES=OUT_BYTES
    OUT_MASK=OUT_MASK
    def __init__(self, seed_int, P_point, Q_point):
        self.seed=seed_int
        self.P=P_point
        self.Q=Q_point
    def genbits(self):
        s=(self.seed*self.P).x
        self.seed=s
        r=(s*self.Q).x
        return r & CSPRNG.OUT_MASK

P=P256.G
d=secrets.randbelow(2**D-2)+2
e=int(pow(d,-1, P256.q))
Q=e*P
seed_bytes=os.urandom(32)
seed_int=int.from_bytes(seed_bytes,'big')
rng=CSPRNG(seed_int,P,Q)
outputs=[rng.genbits() for _ in range(ROUNDS)]
observed_hex=[]
for i in range(ROUNDS-1):
    bits1 = outputs[i]
    bits2 = outputs[i+1]
    obs=(bits1<<(8*2))|(bits2>>(8*(OUT_BYTES-2)))
    observed_hex.append(obs.to_bytes(32,'big').hex())
final_output=outputs[-1]
final_bytes=final_output.to_bytes(OUT_BYTES,'big')
key=final_bytes[:16]
iv=get_random_bytes(16)
cipher=AES.new(key, AES.MODE_CBC, iv)
ct=cipher.encrypt(pad(FLAG,AES.block_size))
challenge={"P":{"x":hex(P.x),"y":hex(P.y)},"Q":{"x":hex(Q.x),"y":hex(Q.y)},"observed":observed_hex,"ciphertext":base64.b64encode(ct).decode(),"iv":base64.b64encode(iv).decode()}
with open('challenge.json','w') as f:
    json.dump(challenge,f,indent=2)