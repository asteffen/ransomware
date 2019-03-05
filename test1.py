from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

BLOCK_SIZE_BYTES = 16
IV_SIZE_BYTES = 16
KEY_SIZE_BYTES = 32
BITS_PER_BYTE = 8

def getHMAC(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    #h.update(b"message to hash")
    #h.finalize()

# Inputs
#   message: bytes
#   key: bytes
# Outputs
#   iv: bytes
#   ct: bytes
def myEncrypt(message, key):
    if len(key) < KEY_SIZE_BYTES:
        raise Exception("Key length is too small")

    backend = default_backend()
    iv = urandom(IV_SIZE_BYTES)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    #message_bytes = bytes(message, "utf8")
    message_bytes = message
    message_padded = pad_data(message_bytes)
    
    # the buffer needs to be at least len(data) + n - 1
    # where n = block size in bytes of the cipher and mode combination
    n = BLOCK_SIZE_BYTES
    bufsize = len(message_padded) + n - 1
    buf = bytearray(bufsize)
    len_encrypted = encryptor.update_into(message_padded, buf)

    ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
    return (iv, ct)

# Inputs
#   ct: bytes
#   iv: bytes
#   key: bytes
# Output
#   message : bytes
def myDecrypt(ct, iv, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # the buffer needs to be at least len(data) + n - 1
    # where n = block size in bytes of the cipher and mode combination
    n = BLOCK_SIZE_BYTES
    bufsize = len(ct) + n - 1
    buf = bytearray(bufsize)
    len_decrypted = decryptor.update_into(ct, buf)
    
    # get the plaintext from the buffer reading only the bytes written (len_decrypted)
    padded_message = bytes(buf[:len_decrypted]) + decryptor.finalize()
    message = unpad_data(padded_message)

    #return message.decode("utf-8")
    return message

# (C, IV, key, ext) = MyfileEncrypt(filepath)
def myFileEncrypt(filepath):
    key = urandom(KEY_SIZE_BYTES)

    fr = open(filepath, "rb")
    message = fr.read()

    (iv, ct) = myEncrypt(message, key)

    fw = open(filepath, "wb")
    fw.write(ct)

    return (ct, iv, key)

def myFileDecrypt(filepath, iv, key):
    fr = open(filepath, "rb")
    ct = fr.read()

    message = myDecrypt(ct, iv, key)

    fw = open(filepath, "wb")
    fw.write(message)

    return (message, iv, key)

# Add PKCS7 padding.
# AES requires the message length to be a multiple of 16 bytes.
# https://cryptography.io/en/latest/hazmat/primitives/padding/
# Input: data as bytes
def pad_data(data):
    padder = padding.PKCS7(BITS_PER_BYTE * BLOCK_SIZE_BYTES).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    return padded_data

# Removes PKCS7 padding.
# Input: padded_data as bytes
def unpad_data(padded_data):
    unpadder = padding.PKCS7(BITS_PER_BYTE * BLOCK_SIZE_BYTES).unpadder()
    data = unpadder.update(padded_data)
    data += unpadder.finalize()
    return data

def test_padding_functions():
    d = b"123456789x123456789x"
    pd = pad_data(d)
    print(pd)
    d2 = unpad_data(pd)
    print(d2)

def test_enc_dec():
    key = urandom(KEY_SIZE_BYTES)
    iv, ct = myEncrypt(b"a secret message12345", key)
    print(iv)
    print(ct)
    message = myDecrypt(ct, iv, key)
    print(message)

def test_file_enc_dec():
    filepath = "demofile.txt"
    #filepath = "cat.jpg"

    print("Press enter to encrypt the file.")
    i = input()
    (ct, iv, key) = myFileEncrypt(filepath)

    print("Press enter to decrypt the file.")
    i = input()
    myFileDecrypt(filepath, iv, key)

test_file_enc_dec()
#test_enc_dec()

#test_padding_functions()