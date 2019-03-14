from os import urandom, remove
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, hmac
from json import dumps, loads

# Constants
BLOCK_SIZE_BYTES = 16
IV_SIZE_BYTES = 16
KEY_SIZE_BYTES = 32
HMAC_KEY_SIZE_BYTES = 16
BITS_PER_BYTE = 8

# for example: b'#F\xdaI\x8b"e\xc4\xf1\xbb\x9a\x8fc\xff\xf5\xdex.
# \xbc\xcd/+\x8a\x86\x1d\x84\'\xc3\xa6\x1d\xd8J'
def getHMAC(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# From hello.txt, return ("hello", "txt")
def getExt(filepath):
    i = len(filepath) - 1
    while i >= 0:
        if filepath[i] == ".":
            break
        i -= 1

    ext = filepath[(i+1):]
    name = filepath[:i]
    return (name, ext)



# Inputs
#   message: bytes
#   key: bytes
# Outputs
#   iv: bytes
#   ct: bytes
# (C, IV)= Myencrypt(message, key)
def myEncrypt(message, key):
    if len(key) < KEY_SIZE_BYTES:
        raise Exception("Key length is too small")
        return

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
    return (ct, iv)

# Encrypt then MAC
def myEncryptMAC(message, EncKey, HMACKey):
    (ct, iv) = myEncrypt(message, EncKey)
    tag = getHMAC(ct, HMACKey)
    return (ct, iv, tag)

# Verify then decrypt
def myDecryptMAC(ct, iv, tag, HMACKey, EncKey):
    tag2 = getHMAC(ct, HMACKey)

    if tag2 != tag:
        raise Exception("The tag is not valid.")
        return

    message = myDecrypt(ct, iv, EncKey)
    return message

# (C, IV, key, ext) = MyfileEncrypt(filepath)
def myFileEncrypt(filepath):
    key = urandom(KEY_SIZE_BYTES)

    fr = open(filepath, "rb")
    message = fr.read()

    (ct, iv) = myEncrypt(message, key)

    fw = open(filepath, "wb")
    fw.write(ct)

    ext = getExt(filepath)

    return (ct, iv, key, ext)

def bytesToString(b):
    #return b.decode('utf-8', 'backslashreplace')
    return b.decode('cp437')

def stringToBytes(s):
    #return s.encode('utf-8', 'backslashreplace')
    #return s.encode('utf-8')
    #return s.decode('unicode-escape').encode('utf-8')
    return s.encode('cp437')

# (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC (filepath)
def myFileEncryptMAC(filepath):
    encKey = urandom(KEY_SIZE_BYTES)
    HMACKey = urandom(HMAC_KEY_SIZE_BYTES)

    fr = open(filepath, "rb")
    message = fr.read()
    (ct, iv) = myEncrypt(message, encKey)

    (name, ext) = getExt(filepath)

    # The input for the HMAC is the ciphertext, not the message.
    # Because we are doing Encrypt-then-MAC.
    tag = getHMAC(ct, HMACKey)

    # Convert bytes variables to string
    encKeyStr = bytesToString(encKey)
    ivStr = bytesToString(iv)
    ctStr = bytesToString(ct)
    tagStr = bytesToString(tag)

    dict1 = {'constant': 'enc', 'encKey': encKeyStr, 'IV': ivStr, 'ciphertext': ctStr, 'ext': ext, 'tag': tagStr}

    newFilepath = name + ".json"

    fw = open(newFilepath, "w")
    fw.write(dumps(dict1))

    print("HMac in encrypt")
    print(HMACKey)
    print("ct in encrypt")
    print(ct)

    # Remove the original file
    # remove(filepath)

    
    return (ct, iv, tag, encKey, HMACKey, ext)

def myFileDecryptMAC(filepath, HMACKey):
    fr = open(filepath, "r")
    fileContent = fr.read()

    jsonDict = loads(fileContent)

    ext = jsonDict['ext']
    encKey = stringToBytes(jsonDict['encKey'])
    iv = stringToBytes(jsonDict['IV'])
    ct = stringToBytes(jsonDict['ciphertext'])
    tag = stringToBytes(jsonDict['tag'])

    #print(ct)
    print("HMac in decrypt")
    print(HMACKey)
    print("ct in decrypt")
    print(ct)

    tag2 = getHMAC(ct, HMACKey)

    if tag2 != tag:
        raise Exception("The tag is not valid.")
        return


# Inputs
#   ct: bytes
#   iv: bytes
#   key: bytes
# Output
#   message : bytes
# (message) = myDecrypt(CT, IV, Key)
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
    (ct, iv) = myEncrypt(b"a secret message12345", key)
    print("iv = " + str(iv))
    print("ct = " + str(ct))
    message = myDecrypt(ct, iv, key)
    print("message = " + str(message))

def test_file_enc_dec():
    filepath = "demofile.txt"
    #filepath = "cat.jpg"

    print("Press enter to encrypt the file.")
    i = input()
    (ct, iv, key, ext) = myFileEncrypt(filepath)
    print("ext = " + ext)

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
    HMACKey = urandom(HMAC_KEY_SIZE_BYTES)
    (ct, iv, tag) = myEncryptMAC(message, EncKey, HMACKey)
    print("ct = ")
    print(ct)
    print("iv = ")
    print(iv)
    print("tag = ")
    print(tag)

    #message2 = myDecryptMAC(ct, iv, tag, HMACKey, EncKey)
    message2 = myDecryptMAC(b"bad", iv, tag, HMACKey, EncKey)
    print(message2)

def test_myFileEncryptMAC():
    filepath = "demofile.txt"
    #(ct, iv, tag, encKey, HMACKey, ext) = myFileEncryptMAC()
    (ct, iv, tag, encKey, HMACKey, ext) = myFileEncryptMAC(filepath)

def test_myFileDecryptMAC():
    filepath = "demofile.txt"
    (ct, iv, tag, encKey, HMACKey, ext) = myFileEncryptMAC(filepath)

    filepath = "demofile.json"
    myFileDecryptMAC(filepath, HMACKey)

def test_json():
    r = {'is_claimed': 'True', 'rating': 3.5}
    str1 = dumps(r)
    print (str1)

def test_ext():
    print(getExt("hello.txt"))

# UTF-8 does not work to encode random bytes.
def test_decode():
    b1 = b'\x00\x01\xffsd'
    #str1 = b1.decode('utf-8')
    str2 = b1.decode('cp437')
    str3 = b1.decode('utf-8', 'backslashreplace')
    print(str2)
    print(str3)

    print(stringToBytes(str3))

#test_myEncryptMAC()
#test_HMAC()
#test_file_enc_dec()
#test_enc_dec()
#test_padding_functions()
#test_myEncryptMAC()
#test_json()
#test_ext()

#test_myFileEncryptMAC()
#test_decode()
test_myFileDecryptMAC()
