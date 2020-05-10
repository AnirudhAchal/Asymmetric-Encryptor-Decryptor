import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()
key = b'\xfa\xd3\x99\x14\xd0<\xc7-\xc2\r\xc0\xb0\no\x9c)/\xf5K\xa2\xdc\xc2\x12C\x81k$\xf1\xc5\x0e\xde\xfa'
iv = b'\xf2\xb8R\xfbG\xe3g\xdc\x0b\x10y\xb1\x85\xfc\xd6\x13'
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
#message=b"a secret messageabc             "
#encryptor = cipher.encryptor()
ct = b'7\xc9\xf5e8!\xd1\x14\xf3kvu7\x97\x8aI\x1d\r\xdb\xbf_`\x1eDQ\x1en\x7f\xb9\x06\xc8\x84'
decryptor = cipher.decryptor()
decryptedmessage=decryptor.update(ct) + decryptor.finalize()
print(decryptedmessage)
