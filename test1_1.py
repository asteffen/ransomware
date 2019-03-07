from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac

BLOCK_SIZE_BYTES = 16
IV_SIZE_BYTES = 16
KEY_SIZE_BYTES = 32
BITS_PER_BYTE = 8

# for example: b'#F\xdaI\x8b"e\xc4\xf1\xbb\x9a\x8fc\xff\xf5\xdex.
# \xbc\xcd/+\x8a\x86\x1d\x84\'\xc3\xa6\x1d\xd8J'
def getHMAC(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Inputs
#   message: bytes
#   key: bytes
# Outputs
#   iv: bytes
#   ct: bytes

#(C, IV)= Myencrypt(message, key)
def myEncrypt(message, key):
    if len(key) < KEY_SIZE_BYTES:
        raise Exception("Key length is too small")

    # Construct an AES-GCM Cipher object with the given key 
    backend = default_backend()
    # and a randomly generated IV.
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
    # update_into(data, buf)
    # return int: Number of bytes written.
    len_encrypted = encryptor.update_into(message_padded, buf)

    # Encrypt the plaintext and get the associated ciphertext.
    ct = bytes(buf[:len_encrypted]) + encryptor.finalize()
    return (iv, ct)

def myEncryptMAC(message, EncKey, HMACKey):
    (iv, ct) = myEncrypt(message, EncKey)
    tag = getHMAC(message, HMACKey)
    return (ct, iv, tag)

# Inputs
#   ct: bytes
#   iv: bytes
#   key: bytes
# Output
#   message : bytes

#(message) = myDecrypt(CT, IV, Key)
def myDecrypt(ct, iv, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    # the buffer needs to be at least len(data) + n - 1
    # where n = block size in bytes of the cipher and mode combination
    n = BLOCK_SIZE_BYTES
    bufsize = len(ct) + n - 1
    buf = bytearray(bufsize)
    # update_into(data, buf)
    # return int: Number of bytes written.
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

# Test info
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

def test_HMAC():
    data = b"message to hash"
    key = urandom(KEY_SIZE_BYTES)

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    sig1 = h.finalize()

    print(sig1)

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    h.verify(sig1)

def test_myEncryptMAC():
    message = b"secret message"
    EncKey = urandom(KEY_SIZE_BYTES)
    HMACKey = urandom(KEY_SIZE_BYTES)
    (ct, iv, tag) = myEncryptMAC(message, EncKey, HMACKey)
    print("ct = ")
    print(ct)
    print("iv = ")
    print(iv)
    print("tag = ")
    print(tag)

    message2 = myDecrypt(ct, iv, EncKey)
    print(message2)

test_myEncryptMAC()
#test_HMAC()
#test_file_enc_dec()
#test_enc_dec()

#test_padding_functions()
