from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
backend=default_backend()


private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=backend)
public_key = private_key.public_key()
pemprivate = private_key.private_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PrivateFormat.PKCS8,
encryption_algorithm=serialization.NoEncryption()
)
pempublic = public_key.public_bytes(
encoding=serialization.Encoding.PEM,
format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Alice")
print(pemprivate)
print(pempublic)