from FileEncryption import *

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

def demo_HMAC_file():
    #filepath = "demofile.txt"
    filepath = "cat.jpg"

    print("Press enter to encrypt the file.")
    i = input()
    (ct, iv, tag, encKey, HMACKey, ext) = myFileEncryptMAC(filepath)

    HMACKey = getHMACKey()
    #filepath2 = "demofile.json"
    filepath2 = "cat.json"

    print("Press enter to decrypt the file.")
    i = input()
    message = myFileDecryptMAC(filepath2, HMACKey)

def test_myFileDecryptMAC():
    filepath = "demofile.txt"
    (ct, iv, tag, encKey, HMACKey, ext) = myFileEncryptMAC(filepath)

    filepath = "demofile.json"
    message = myFileDecryptMAC(filepath, HMACKey)

    print(message)

def test_HMAC():
    data = b"message to hash"
    key = urandom(KEY_SIZE_BYTES)

    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    sig1 = h.finalize()

    print(sig1)
    print(type(sig1))

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
test_decode()
#test_myFileDecryptMAC()
#demo_HMAC_file()
#test_HMAC()
