from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# توليد المفتاح الخاص
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# توليد المفتاح العام من الخاص
public_key = private_key.public_key()

# حفظ المفتاح الخاص
with open("private_key.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ))

# حفظ المفتاح العام
with open("public_key.pem", "wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("مفاتيح RSA تم توليدها وحفظها ✅")
