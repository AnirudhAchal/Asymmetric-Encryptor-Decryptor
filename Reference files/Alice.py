import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
message= "a secret messageabc".encode()
encryptor = cipher.encryptor()
ct = encryptor.update(message) + encryptor.finalize()

#decryptor = cipher.decryptor()
#decryptor.update(ct) + decryptor.finalize()
print(key)
print(iv)
print(message)
print(ct)