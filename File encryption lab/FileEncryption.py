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
DEBUG = False

# Using a constant HMACKey to make it possible to demo.
def getHMACKey():
    return urandom(HMAC_KEY_SIZE_BYTES)
    #return b'\xffN[\xa7\x93\x9d8\xea!\x15\xb2^=\xebQ\xd1'

def getEncKey():
    return urandom(KEY_SIZE_BYTES)

# Encrypt then MAC
def myEncryptMAC(message, EncKey, HMACKey):
    (ct, iv) = myEncrypt(message, EncKey)

    # The input for the HMAC is the ciphertext, not the message.
    # Because we are doing Encrypt-then-MAC.
    tag = getHMAC(ct, HMACKey)
    return (ct, iv, tag)

# return (C, IV, tag, Enckey, HMACKey, ext)
def myFileEncryptMAC2(filepath):
    with open(filepath, "rb") as fr:
        message = fr.read()

    encKey = getEncKey()
    HMACKey = getHMACKey()
    (name, ext) = getExt(filepath)

    (ct, iv) = myEncrypt(message, encKey)
    tag = getHMAC(ct, HMACKey)

    return (ct, iv, tag, encKey, HMACKey, ext)

# (C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC (filepath)
def myFileEncryptMAC(filepath):
    encKey = urandom(KEY_SIZE_BYTES)
    HMACKey = getHMACKey()

    with open(filepath, "rb") as fr:
        message = fr.read()

    (name, ext) = getExt(filepath)
    (ct, iv, tag) = myEncryptMAC(message, encKey, HMACKey)

    # Convert bytes variables to string
    encKeyStr = bytesToString(encKey)
    ivStr = bytesToString(iv)
    ctStr = bytesToString(ct)
    tagStr = bytesToString(tag)

    jsonDict = {'constant': 'enc', 'encKey': encKeyStr, 'IV': ivStr, 'ciphertext': ctStr, 'ext': ext, 'tag': tagStr}

    newFilepath = name + ".json"
    with open(newFilepath, "w") as fw:
        fw.write(dumps(jsonDict))

    if DEBUG:
        print("HMac in encrypt")
        print(HMACKey)
        print("ct in encrypt")
        print(ct)

    # Delete the original file.
    remove(filepath)

    return (ct, iv, tag, encKey, HMACKey, ext)




# Get HMAC for the data and key.
def getHMAC(data, key):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# For filepath=hello.txt, return ("hello", "txt")
def getExt(filepath):
    i = len(filepath) - 1
    while i >= 0:
        if filepath[i] == ".":
            break
        i -= 1
    if i == -1:
        raise Exception("Filepath does not contain a period.")

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
    fr.close()

    (ct, iv) = myEncrypt(message, key)

    fw = open(filepath, "wb")
    fw.write(ct)
    fw.close()

    ext = getExt(filepath)

    return (ct, iv, key, ext)

# Using cp437 instead of utf-8.
# This is because trying to decode random bytes in utf-8 results in an error.
def bytesToString(b):
    #return b.decode('utf-8', 'backslashreplace')
    return b.decode('cp437')

def stringToBytes(s):
    #return s.encode('utf-8', 'backslashreplace')
    return s.encode('cp437')



def myFileDecryptMAC(filepath, HMACKey):
    with open(filepath, "r") as fr:
        fileContent = fr.read()

    # Delete the json file.
    remove(filepath)

    jsonDict = loads(fileContent)

    ext = jsonDict['ext']
    encKey = stringToBytes(jsonDict['encKey'])
    iv = stringToBytes(jsonDict['IV'])
    ct = stringToBytes(jsonDict['ciphertext'])
    tag = stringToBytes(jsonDict['tag'])

    if DEBUG:
        print("HMac in decrypt")
        print(HMACKey)
        print("ct in decrypt")
        print(ct)

    # myDecryptMAC will recompute the tag and raise an error if the tag is invalid.
    message = myDecryptMAC(ct, iv, tag, HMACKey, encKey)

    (name, ext2) = getExt(filepath)
    origFilepath = name + "." + ext

    with open(origFilepath, "wb") as fw:
        fw.write(message)

    return message

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
    fr.close()

    message = myDecrypt(ct, iv, key)

    fw = open(filepath, "wb")
    fw.write(message)
    fw.close()

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

