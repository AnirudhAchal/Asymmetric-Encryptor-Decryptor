import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
backend = default_backend()



BOBprivate_key_serealized=b'-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpyD8iLKKijxja\nzawqOHYB+3RqrB0iFwx5Smnst6jiLMcmh5v5sozI2W6JCqxlCK6OfaucG50T6aUH\n7ciKeCzKNvDOa0Yh6QuI18/p2pSHVYpPx0OpP2TZSEqkXYtdSxhbgxlqtFv1N9Ek\n+rjsYnTRdgomlH1sXoGcI+9DVA5uQjVWY9tRupEn5vTpAZS6OK8edMkMIyRKLRP6\nicPLvZp4gqvTn3LwInAVPKaLTowojCUGCLURqOZSIqFtMkA3D5VTs9on8+rOnNMZ\nJNUsCti9+lVUoxnyVZFTZkz1JQ/4FxsSvpLfd/GyLp+edXTWFixtRWzCe+JBM3uP\ndRQJ4qlnAgMBAAECggEAdsw6QMx7zK14zN9NCJtuZC16iCZ0G3mo7g3Ba/gcSurE\nPLEWsrlnzzymbd9NoX3a7i+wQADMPm0xXqkXij3tTMjEb7CVj+/T27MHRWe8qFTw\nlv/EQ0IipkOVIpcilcLuWrpw9Qc335GApxD9XanegP5BxD8ayTHxHP4pvIX/W0kz\nGNV1uHTlDfASytC7g4k4zSO6zweIc2x4c/sMzc9yxGb+vrB+G0ArFBi/s21btLnm\nL2tbi6VDCwgpTplh/4GIOrZLHw8P4+igvcBZ1CKd2kr+RoH0gnoHOEXZBKCcwlWI\nWWK+TM4G4TPqMAah2i2jfBf13ViT3E7cxJvsc0EPqQKBgQD3kvd9nRaFqjR/4fFD\n4yg/MvY62Ab55GKL8tis8RYJkF6eIm9SMOR0sSyZZvcJRKJlQyxF0NRji5ZQczU5\n3CqDoM0SaW0FbzdQENOaQVPThshl9am0eB5sZQVyAsdeXijThvkdBdarsBNAnW2v\nPHsrumWYeYaJQjSgvujCviuQTQKBgQDxvR2dvyLyEE9nk4I/+QcCpYAMEn/2UY1I\nR0BsMjsFb2M9TNUbl05aTs86fHcQvN2+HxPpchj5PstQ+nWs4RkU1U/orDEpz2hO\nDvk5l0jXv2rgPTgFr7pm6/TX0nm5qlUkP3gxboBiHDDC0fLrAaMzHLKhSYAyPTdY\njBUZeLAagwKBgQDq6k9gp/A5ANo0BkaSbjdAULEIAPgNokJIHTSwVUrd5FmDn5UV\n3kLI3108alE6QCAACg82aANAObF1wPveXSUSJUCxmcvS/kbz+CNxGU/bROdeqA5R\nqjDkFa9nEW/wAVSn8kjq2yFpY/fAtiDfyHnvcjz4w0d/cozRgpUGRMC9eQKBgHTm\n/MSFY1PmWVAAgLOJLT+1Y1fzNlibFZTHiDsKi4pUVIyXdFN0d1qq1AI3oKjCfQVt\nKAbzu2oFWPNfO7sP3D477fnaE6hhedKN4S5dn8dd9URdtpLhaWZOY0hfq6gC3Eu8\nOdbF1mYbteTw/OVzFEYqcaQX1Fv3SKWUkLuRprAbAoGBALY3mkbRYj3d90fUvzXK\niS8b6toOO637mtjcPwE9aRm5PGRrFyTKObsWApSkEkKRfys69nrCtKAqD7BHHjhN\nwJroi34RkeP8XnndIFIcwwSqB7sFAFyWvN3tN4wyUppVnT6w8t2SWOJZWxceqX4C\nDfwS0xIwHAmT8xr9WMkv2K22\n-----END PRIVATE KEY-----\n'
BOBprivate_key = serialization.load_pem_private_key(
BOBprivate_key_serealized,
password=None,
backend=default_backend()
)


keyciphertext=b"3\xb8'\x19\x91g\xb2!\xd8pc\xd7\x80\xbe\xeck8\xc1\xb3\xc3U\xae\xbc\xacz\xbcVt\xcb%puJq&\x80\xb2]\xb18\xb18\x89\xb2\x87\xc5zB\x7f\xda\xc7\xd1\x10\xfah\xc1g\xcf3\xc1\xc5\xfa\xf7\x08\x14\x17E\xd7\x00\xff\xa2\x85\xc3\x08:<\x85\xe4(K\xf6O\xb5\xac\x98\x16\x9a/\xe5\xde\xde\xe6\xaa<2\xb6\x10\xe3\x19\xdfO\xb3\xafa6\xc9\xa7W>\xd7N\x04\xebec\x9a\xfb\xca\x1et\x0f\xa1]\xbcn\x04\x83\xef\xbe\xd9\xcbs\x8a\x1d\xa9J\x12\xa7\xb2\xdb<\xb0\xec\xe5\x95\xc2\x9e\xc8\xbf<_a[\xbb\xe1I\xaaU\xd3\x0b\x12\x8c\xe2/\xb9\xc5\xec\x1d7O@j\xd2\xce\n\xaa||\xda+\xbc\xfb\xe9es\xc9hjz\xae]\x93+\xc5)\xd3\xeb\x1c\x0fQ\xf9\xe7+\x87\xc0#E\x15\xaeUA\xd8:\xfd\xcd\xaeNV\xec\x14\xaa9\xff\xcf\x03\x88)\x19#\xae\xc1\x15\xc7\xea\xfeu\x87\xeaV%R\xcdt\x96!v\xe9Xf\xe6`\x00\x18\x16\x84\x06"

ivciphertext=b'\x90\xe3Q\xa5\xe9`&\xf3\xc3j\xe0\xc3\xd7\xcf\x18\xd4JH3\x1eu-EeB\x88\x90\xe5\xdf\x9a\x87=\x9d"\xca[\xbc\xbd\x80\xf8)o$A\x94\xb01Q\x87X"\xd4\n\xd3\x90\xdd\xbe\xd8\xa26\x81\xc6\xc8p\x19\x7f\xdez\x8a\x84wcrEB\xadx\xcb\xab3~3\x90J\xfc\x95\xf6\x84\x07y5\x105\x1c\xf2\xf95\x83R+\xe3t\xcc$\xef\xca9\xa0\xcd\xbd\xc3\x87\xc7\x94\x90\x1c\xdaC[\x88.c\xe7|\x8c\xec\xfcY\x07\xa0\x03\x07dS\x0c}h\\\x15\'5\x8c\x0b\xd6\xac\xeb1\xaf\xd5\xeeo\xc1i\xf0\x82\x9e\xc0\x9e\xb0\xb4\x80v\x1e#{D\x04\x1c\x9f1\xaf\xa58\xc3\x1c\x0f\xb9\xc1\x9b\x94\x89\x13~\xfd\xc6\xd1\x9b\xf0>c\x85lIxU\xfd\x9a\x0e\xc3z\xf4\x15\xcc\x9e\xa4\xd6\xa1\xe3\xb8\xa4.\x9f5\xf3\xe1\x0c\x91|\x88\xfeU\xe7\xa5Y\xe7\xdb\xb5\xafj\xe0\xc6\xa7\xb1%\x00\xdb\x10\xb4\x81\x1c\xb2\x93\xf4\xbe\x8dF3\xf4y9C\xd1D\xffAZ'


key = BOBprivate_key.decrypt(
keyciphertext,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None
)
)


iv = BOBprivate_key.decrypt(
ivciphertext,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None
)
)


ALICEpublic_key_serealized=b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9YhSWQsxLCuShypYrjEt\n+03qXFAaLL8WpLyikTuG1rtAyjjooCi4UXw/MV1WW1YaGE13IAe+bK9peWHk4kbj\n/U4RVXKF5v/rs4LjjVdXDJnHja+1ls83fRsm9nbVyVMwzedx/t5QYFJkU9ADPQyb\nht9keIjDpMHpxQCMJDJClTbc+qQKqeTnFsEM+XDSKhybzsxs6oEh5LDyrEP5j/5g\nSu8DSbYBAx6vF1ZN8SrBD+D7HRjUy9PYTG7ILkFExQvDr8TwbxwdBzztkxBnj6Fn\nvWVf5YQIbfLyDVmFuXsrB/yx3tGki+H9xuDOEbAo4ubdeN/mFW/m6qJ46K2dPNHA\n/QIDAQAB\n-----END PUBLIC KEY-----\n'

ALICEpublic_key = serialization.load_pem_public_key(
ALICEpublic_key_serealized,
backend=default_backend()
)


print(key)
print(iv)

signature=b"\x85\x1e\xba\xfd\xf4q\xc9\x17\xa2|\x85.z\x00nL\x16\x7f\xb3\xa4\xd3\x02\xac\xda\xff\x85\xf5I\x8d\x1a\xfa!=\r\xd9\x0b\x99\x13\xc5rw.qL\x00\xaf\xc0\xbe\xe9|\xc22k[\xe0= lgQ\x9c~6\xbd\x81\x85\xbbp\xf9[\x10\xc6$\xaa\xd3vr\x95m\xfc\x07\xb4\x95\x85QD4\xe9\x82\x8b\xa6\xe01\x86\xf7\xfe\x83\xe1hL\xf6\x16\xfa\x02\x8f\x87Z!\x80\r\xce6\x15\xab@M]'J]T\xc8\th\x94O\xd0z\xa9'\x886z\xbb\xa9t\xb3\xda\xff;\x9d\xaee\xd5sBW?\xdff\x9by!\xb4\x99\xcb0\x1d\xbdX\xa0\x87\xa6Q\xb0k\xee?\xda=\xbd\xa8\xae\xd2u\xf9\xe1\xaf\x84\xe5+\xf7\x9e\xbcl\xad\x91Lq\x86.\xee\x02Z\xde[\xe6H\xcdu\xda\x97\x96\xc5)\x89+\xc1!\x80\xe8\xf7\x9a\x8e\x07*E\xf3\xa5\x08\xdbG\xcd\xe0\x14+G\xc1g\xd5\x7fPv\x90\xf6\x93\xf3\xd3m\x84\xd2\x00J\xda.\x17\xde\x9d]K\x83\xc2\x06\x8b\x80\xe5"
checkmessage=b"A message I want to sign"

ALICEpublic_key.verify(
signature,
checkmessage,
padding.PSS(
mgf=padding.MGF1(hashes.SHA256()),
salt_length=padding.PSS.MAX_LENGTH
),
hashes.SHA256()
)