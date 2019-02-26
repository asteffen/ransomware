# from cryptography.hazmat.primitives.ciphers.algorithms import AES

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
encryptor = cipher.encryptor()

# the buffer needs to be at least len(data) + n - 1 where n is cipher/mode block size in bytes
buf = bytearray(31)
len_encrypted = encryptor.update_into(b"a secret message", buf)

# get the ciphertext from the buffer reading only the bytes written to it (len_encrypted)
ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
decryptor = cipher.decryptor()
len_decrypted = decryptor.update_into(ct, buf)
# get the plaintext from the buffer reading only the bytes written (len_decrypted)


def myEncrypt(message, key):
    if len(key) < 32:
        print("Error: Key is less than 32 bytes.")
        return

    message_bytes = bytes(message, "utf8")
    iv = os.urandom(16)
    return message_bytes

#print (ct)
#print (bytes(buf[:len_decrypted]) + decryptor.finalize())
#print (key)
#print(len(key))
print(myEncrypt("test", key))

