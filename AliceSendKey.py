import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
backend = default_backend()
key = b'\x05\xbe\xaa\x04\xb4\x11\xc3\xce\x10\xef\xbfT\xc6\x0e\x85\x10\xd7\x90\x7f\xdb\xe4^\xed\xcc\x80=\xeb\xdba\xeeQ\x14'
iv = b'\xbd7\xa4\xda+\xd0\x8e\xcf\xfe\xb5w\x83\xa6\xb0\x9d\xe7'




BOBpublic_key_serealized=b'-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6cg/Iiyioo8Y2s2sKjh2\nAft0aqwdIhcMeUpp7Leo4izHJoeb+bKMyNluiQqsZQiujn2rnBudE+mlB+3Iings\nyjbwzmtGIekLiNfP6dqUh1WKT8dDqT9k2UhKpF2LXUsYW4MZarRb9TfRJPq47GJ0\n0XYKJpR9bF6BnCPvQ1QObkI1VmPbUbqRJ+b06QGUujivHnTJDCMkSi0T+onDy72a\neIKr059y8CJwFTymi06MKIwlBgi1EajmUiKhbTJANw+VU7PaJ/PqzpzTGSTVLArY\nvfpVVKMZ8lWRU2ZM9SUP+BcbEr6S33fxsi6fnnV01hYsbUVswnviQTN7j3UUCeKp\nZwIDAQAB\n-----END PUBLIC KEY-----\n'

BOBpublic_key = serialization.load_pem_public_key(
BOBpublic_key_serealized,
backend=default_backend()
)


keyciphertext = BOBpublic_key.encrypt(
key,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None)
)

ivciphertext= BOBpublic_key.encrypt(
iv,
padding.OAEP(
mgf=padding.MGF1(algorithm=hashes.SHA256()),
algorithm=hashes.SHA256(),
label=None)
)

ALICEprivatekeyserealise=b'-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQD1iFJZCzEsK5KH\nKliuMS37TepcUBosvxakvKKRO4bWu0DKOOigKLhRfD8xXVZbVhoYTXcgB75sr2l5\nYeTiRuP9ThFVcoXm/+uzguONV1cMmceNr7WWzzd9Gyb2dtXJUzDN53H+3lBgUmRT\n0AM9DJuG32R4iMOkwenFAIwkMkKVNtz6pAqp5OcWwQz5cNIqHJvOzGzqgSHksPKs\nQ/mP/mBK7wNJtgEDHq8XVk3xKsEP4PsdGNTL09hMbsguQUTFC8OvxPBvHB0HPO2T\nEGePoWe9ZV/lhAht8vINWYW5eysH/LHe0aSL4f3G4M4RsCji5t143+YVb+bqonjo\nrZ080cD9AgMBAAECggEBALqu1JW5ScDgvD8i9lwzLlflrOxVRyGAhNHqTtyH2wTH\nSQK4dD7Z1xK1mkKJShCWDa8urwVefe2bDWHqCaH17oD463sBYUf6i5ZoTWV448nD\n3pMe5r1sfi8UBvLb9b5mDzRu5iC3nXsvCfMjtGKlhFbu4TA4JDDP81MDEIqw4Ckc\nGXX6V1nh1NegSAZdwzSTdRrwacBzUdd4dRMlSlpSfWoCzd8W9/gY97rVIdPYcGlF\nvPqgXkxZT0h81iQ+Du9itgMozZbKbutFFIxMO+ClwN6HPLBahvIz92HhZWa8OG5C\nUS7108rYRZnIEAM6lQDoDUtGTjUfJMXIua3UoapsxMECgYEA+9hz96rkRPG0LACq\nZDRcnsZRJ9OsF9ezQhbr5zf5+lsKZBKRN6HisUrxjeEt6jgyK3r3LiI3/hWm77nv\nYvfoRe5Gu1zzCnU5KVGNabkwEHCH9aJjQjqJiZXYtY3LFIhUnvWn3EcRm1QdPBLv\n2Zt5JiwNLvY4lTzZiSQHQQumzVECgYEA+ZU1b6aqiMSWLqITFuRN846yqNyLy+sF\nEyZTC2eqwlwByIw2YJvn3VR6bWoaunGJcwl6HtD8Mvtic8x20KueKLGZKlnVpnEC\nzoy2H/joTx/7h8joxJ1dQ9YzNB3EWC9nYmsc5LZK1hWfHCnXk5iOQE/xlFFeBApO\nCyS3NsULne0CgYB87ujAgQ8SQJEvjvj4Ep2ryheyWSgy/7cWXwaRwkwI7Sbfc/KE\nFZO+fb4Msxsy6MPCnBKI2ULLkfQpUiS2BOM95bFC+x46HuLHY4RyYQK99QUNToxM\n63sVPLevgPKwcd0Aqj6mYL8UPgrupTpEygK0c//qPwzcw73qcWwD0YLisQKBgHMb\n4ANYqPpfQKzNT2SVc2ZLgBblcQxhnnuQh2iRLW5qpN/r2wB/p1arKbPg5ebrimsm\nCc7AsDCLRIMH4Bypqk42at/fguw63wKIX08rq2ki5Q1hGgnkUimBVyhIOlA5vMLl\nh/PsJ2PJoRKKMcT+7Uy4EkFHrcbLQeddzapTAuKZAoGBAOuIUqtGbsG5gzxd3kw7\nndGZt575cKclifKC8Xn8IF5IHHL0J0cW3yp7WU7tUpCId3tuk4Ccc2iN/blefKWA\nIZb8QxhuOwDvPMXtqvE35J+NImkz+NebtV3AD7kJpMBU/bFC7eFEJMFYPtmo4PzM\n29WJMtrZW6LDv7ba+ztMyNsF\n-----END PRIVATE KEY-----\n'
ALICEprivate_key = serialization.load_pem_private_key(
ALICEprivatekeyserealise,
password=None,
backend=default_backend()
)


message = b"A message I want to sign"
signature = ALICEprivate_key.sign(
message,
padding.PSS(
mgf=padding.MGF1(hashes.SHA256()),
salt_length=padding.PSS.MAX_LENGTH
),
hashes.SHA256()
)


print(keyciphertext)
print(ivciphertext)
print(signature)


#print("1->Generate Alice's pair of public and private keys")
#print("2->Generate bob's pair of public and private keys")
#print("3->Send a symmetric key from alice to bob")
#print("4->Recieve the key")
#print("5->Send a message form alice")
#print("6->Send a message form bob")
#alicevar.sendmessage()
#while(1)
    #take input
    #if the input is 1->
#    2->
#    3->

    #exit->
    #break;


#class {

#}
#bob,alice
#public->public key
#private->private key,symmetric key+iv



#1
#2
#3
#4
#ALSO maintain logs
