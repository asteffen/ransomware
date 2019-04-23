from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from os.path import isfile, join, splitext
from os import remove, walk
from json import dumps, loads
from platform import system
import FileEncryption

PUBLIC_EXPONENT = 65537
KEY_SIZE_BITS = 2048
# RSA_PUBLIC_KEY_FILEPATH = "./public.pem"
# RSA_PRIVATE_KEY_FILEPATH = "./private.pem"

OS = system()
if OS == 'Darwin':
    PROJECT_DIRECTORY = "/Users/xinbeishen/Desktop/CSULB/CECS 378/CECS378-master/CECS378"
else if OS == 'Windows':
    PROJECT_DIRECTORY = "C:/stuff/school2/_2019spring/cecs378/CECS378"
else:
    raise Exception('Unsupported OS')

ENCRYPTION_DIRECTORY = join(PROJECT_DIRECTORY, "File encryption lab/TestDir")
RSA_PRIVATE_KEY_FILEPATH = join(PROJECT_DIRECTORY "File encryption lab/private.pem")
RSA_PUBLIC_KEY_FILEPATH = join(PROJECT_DIRECTORY "File encryption lab/public.pem")
DO_NOT_ENCRYPT_LIST = [RSA_PUBLIC_KEY_FILEPATH, RSA_PRIVATE_KEY_FILEPATH]

# This function does step 1.
# If either pem file does not exist, generate keys and create the files.
def checkAndCreatePEMFiles():
    public_exists = isfile(RSA_PUBLIC_KEY_FILEPATH)
    private_exists = isfile(RSA_PRIVATE_KEY_FILEPATH)

    if (not public_exists) or (not private_exists):
        (private_key, public_key) = generateRSAKeys()
        writeRSAKeyFile(RSA_PRIVATE_KEY_FILEPATH, private_key, True)
        writeRSAKeyFile(RSA_PUBLIC_KEY_FILEPATH, public_key, False)

def generateRSAKeys():
    private_key = generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return (private_key, public_key)

# Return OAEP padding object.
def getPadding():
    p = padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
    return p

def RSAEncrypt(message, public_key):
    ciphertext = public_key.encrypt(message, getPadding())
    return ciphertext

def RSADecrypt(ciphertext, private_key):
    message = private_key.decrypt(ciphertext, getPadding())
    return message

# Load the key object from the pem file.
# is_private: Boolean which specifies whether the key is private or public.
def loadRSAKeyFile(filepath, is_private):
    if is_private:
        with open(filepath, "rb") as key_file:
            key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    else:
        with open(filepath, "rb") as key_file:
            key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )

    #public_key = private_key.public_key()
    return key

# Write the key object to the pem file.
# is_private: Boolean which specifies whether the key is private or public.
def writeRSAKeyFile(filepath, key, is_private):
    if is_private:
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(filepath, "wb") as key_file:
        key_file.write(pem)

# splits key into encKey and HMACKey
def splitKey(key):
    #encKey = key[0:32]
    #HMACKey = key[32:48]
    KEY_SIZE_BYTES = FileEncryption.KEY_SIZE_BYTES
    HMAC_KEY_SIZE_BYTES = FileEncryption.HMAC_KEY_SIZE_BYTES
    encKey = key[0 : KEY_SIZE_BYTES]
    HMACKey = key[KEY_SIZE_BYTES : KEY_SIZE_BYTES + HMAC_KEY_SIZE_BYTES]
    return (encKey, HMACKey)

# Calculates the values (RSACipher, C, IV, tag, ext).
# Does not modify the file.
def MyRSAEncrypt(filepath, RSA_publickey_filepath):
    (ct, iv, tag, encKey, HMACKey, ext) = FileEncryption.myFileEncryptMAC2(filepath)

    public_key =  loadRSAKeyFile(RSA_publickey_filepath, False)

    key = encKey + HMACKey
    RSACipher = RSAEncrypt(key, public_key)

    return (RSACipher, ct, iv, tag, ext)

# Creates JSON file.
# Deletes the original filepath.
def MyRSAEncryptFile(filepath, RSA_publickey_filepath):
    # This calls myFileEncryptMAC2 which generates the encKey and HMACKey.
    (RSACipher, ct, iv, tag, ext) = MyRSAEncrypt(filepath, RSA_publickey_filepath)

    (name, _) = splitext(filepath)

    # Convert bytes variables to strings
    bytesToString = FileEncryption.bytesToString
    RSACipherStr = bytesToString(RSACipher)
    ivStr = bytesToString(iv)
    ctStr = bytesToString(ct)
    tagStr = bytesToString(tag)

    jsonDict = {
        'RSACipher': RSACipherStr,
        'ciphertext': ctStr,
        'iv': ivStr,
        'tag': tagStr,
        'ext': ext}

    newFilepath = name + ".json"
    with open(newFilepath, "w") as fw:
        fw.write(dumps(jsonDict, indent=4))

    # Delete the original file.
    remove(filepath)

    return (RSACipher, ct, iv, tag, ext)


# decrypts JSON file.
# writes the plaintext to original filepath.
# Deletes the json file.
def MyRSADecryptFile(filepath, RSA_privatekey_filepath):
    with open(filepath, "r") as fr:
        fileContent = fr.read()
    jsonDict = loads(fileContent)

    # Delete the json file.
    remove(filepath)

    stringToBytes = FileEncryption.stringToBytes
    ext = jsonDict['ext']
    RSACipher = stringToBytes(jsonDict['RSACipher'])
    iv = stringToBytes(jsonDict['iv'])
    ct = stringToBytes(jsonDict['ciphertext'])
    tag = stringToBytes(jsonDict['tag'])

    message = MyRSADecrypt(RSACipher, ct, iv, tag, ext, RSA_privatekey_filepath)

    (name, _) = splitext(filepath)
    origFilepath = name + "." + ext

    with open(origFilepath, "wb") as fw:
        fw.write(message)

    return message

# message = MyRSADecrypt(RSACipher, C, IV, tag, ext)
def MyRSADecrypt(RSACipher, ct, iv, tag, ext, RSA_privatekey_filepath):
    private_key =  loadRSAKeyFile(RSA_privatekey_filepath, True)
    key = RSADecrypt(RSACipher, private_key)
    (encKey, HMACKey) = splitKey(key)

    message = FileEncryption.myDecryptMAC(ct, iv, tag, HMACKey, encKey)
    return message

def encryptDir(directory, RSA_publickey_filepath):
    for root, dirs, files in walk(directory, topdown=False):
        for name in files:
            filepath = join(root, name)

            # do not encrypt the files in DO_NOT_ENCRYPT_LIST
            if filepath in DO_NOT_ENCRYPT_LIST:
                continue

            MyRSAEncryptFile(filepath, RSA_publickey_filepath)
            print("Encrypted file: " + filepath)

def decryptDir(directory, RSA_privatekey_filepath):
    for root, dirs, files in walk(directory, topdown=False):
        for name in files:
            filepath = join(root, name)

            # make sure it is a json file.
            (_, ext) = splitext(filepath)
            if ext != '.json':
                continue

            MyRSADecryptFile(filepath, RSA_privatekey_filepath)
            print("Decrypted file: " + filepath)

def test_RSAEncrypt():
    message = b"encrypted data23"
    (private_key, public_key) = generateRSAKeys()
    ciphertext = RSAEncrypt(message, public_key)
    message2 = RSADecrypt(ciphertext, private_key)

    print("ct=")
    print(ciphertext)
    print("message2=")
    print(message2)

def test_writeRSAKeyFile():
    (private_key, public_key) = generateRSAKeys()
    writeRSAKeyFile(RSA_PRIVATE_KEY_FILEPATH, private_key, True)
    writeRSAKeyFile(RSA_PUBLIC_KEY_FILEPATH, public_key, False)

def test_loadRSAKeyFile():
    pub =  loadRSAKeyFile(RSA_PUBLIC_KEY_FILEPATH, False)
    priv = loadRSAKeyFile(RSA_PRIVATE_KEY_FILEPATH, True)
    print(pub, priv)

# KEY_SIZE_BYTES = 32
# HMAC_KEY_SIZE_BYTES = 16
def test_MyRSAEncrypt():
    filepath = "demofile.txt"
    RSA_publickey_filepath = RSA_PUBLIC_KEY_FILEPATH
    (RSACipher, C, IV, tag, ext) = MyRSAEncrypt(filepath, RSA_publickey_filepath)

    RSA_privatekey_filepath = RSA_PRIVATE_KEY_FILEPATH
    message = MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_privatekey_filepath)
    print(message)

def test_MyRSAEncryptFile():
    filepath = "demofile.txt"
    RSA_publickey_filepath = RSA_PUBLIC_KEY_FILEPATH
    MyRSAEncryptFile(filepath, RSA_publickey_filepath)

def test_MyRSADecryptFile():
    filepath = "demofile.json"
    RSA_privatekey_filepath = RSA_PRIVATE_KEY_FILEPATH
    MyRSADecryptFile(filepath, RSA_privatekey_filepath)

def demo_MyRSAEncryptFile():
    print("Press enter to encrypt the file.")
    i = input()
    test_MyRSAEncryptFile()

    print("Press enter to decrypt the file.")
    i = input()
    test_MyRSADecryptFile()

def test_encryptDir(directory):
    RSA_publickey_filepath = RSA_PUBLIC_KEY_FILEPATH
    encryptDir(directory, RSA_publickey_filepath)

def test_decryptDir(directory):
    RSA_privatekey_filepath = RSA_PRIVATE_KEY_FILEPATH
    decryptDir(directory, RSA_privatekey_filepath)

def demo_encryptDir():
    directory = "./TestDir"
    print("Press enter to encrypt the file.")
    i = input()
    test_encryptDir(directory)

    print("Press enter to decrypt the file.")
    i = input()
    test_decryptDir(directory)

def main_encryptDir():
    checkAndCreatePEMFiles()
    
    directory = ENCRYPTION_DIRECTORY
    RSA_publickey_filepath = RSA_PUBLIC_KEY_FILEPATH
    encryptDir(directory, RSA_publickey_filepath)
    i = input()

def main_decryptDir():
    directory = ENCRYPTION_DIRECTORY
    RSA_privatekey_filepath = RSA_PRIVATE_KEY_FILEPATH
    decryptDir(directory, RSA_privatekey_filepath)
    i = input()

#test_RSAEncrypt()
#test_writeRSAKeyFile()
#test_loadRSAKeyFile()
#test_MyRSAEncrypt()
#test_MyRSAEncryptFile()
#test_MyRSADecryptFile()
#demo_MyRSAEncryptFile()

#checkAndCreatePEMFiles()
#test_encryptDir()
#test_decryptDir()
#demo_encryptDir()

#checkAndCreatePEMFiles()
#demo_encryptDir()

#main_decryptDir()
#main_encryptDir()