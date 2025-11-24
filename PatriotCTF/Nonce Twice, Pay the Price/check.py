from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

d = int("3d5d238dfd8ccd1472cd22f80e22ae57e9ad79d779f4630930efb5cc21977ce7",16)
priv = ec.derive_private_key(d, ec.SECP256K1(), default_backend())
pem = priv.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
open("recovered_priv.pem","wb").write(pem)
print("Saved recovered_priv.pem")
