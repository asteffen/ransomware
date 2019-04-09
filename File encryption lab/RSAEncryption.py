from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from os.path import isfile
import FileEncryption


PUBLIC_EXPONENT = 65537
KEY_SIZE_BITS = 2048
RSA_PUBLIC_KEY_FILEPATH = "public.pem"
RSA_PRIVATE_KEY_FILEPATH = "private.pem"

# This function does step 1. If the file does not exist,
# generate keys create the file.
# Return public and private keys.
def step1():
    public_exists = isfile(RSA_PUBLIC_KEY_FILEPATH)
    private_exists = isfile(RSA_PRIVATE_KEY_FILEPATH)

    if (not public_exists) or (not private_exists):
        (private_key, public_key) = generateRSAKeys()
        writeRSAKeyFile(RSA_PRIVATE_KEY_FILEPATH, private_key, True)
        writeRSAKeyFile(RSA_PUBLIC_KEY_FILEPATH, public_key, False)

    return (private_key, public_key)

def generateRSAKeys():
    private_key = generate_private_key(
        public_exponent=PUBLIC_EXPONENT,
        key_size=KEY_SIZE_BITS,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return (private_key, public_key)

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

# (RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath):
def MyRSAEncrypt(filepath, RSA_publickey_filepath):
    (ct, iv, tag, encKey, HMACKey, ext) = FileEncryption.myFileEncryptMAC2(filepath)

    public_key =  loadRSAKeyFile(RSA_publickey_filepath, False)

    key = encKey + HMACKey
    RSACipher = RSAEncrypt(key, public_key)

    return (RSACipher, ct, iv, tag, ext)

# splits key into encKey and HMACKey
def splitKey(key):
    #encKey = key[0:32]
    #HMACKey = key[32:48]
    KEY_SIZE_BYTES = FileEncryption.KEY_SIZE_BYTES
    HMAC_KEY_SIZE_BYTES = FileEncryption.HMAC_KEY_SIZE_BYTES
    encKey = key[0 : KEY_SIZE_BYTES]
    HMACKey = key[KEY_SIZE_BYTES : KEY_SIZE_BYTES + HMAC_KEY_SIZE_BYTES]
    return (encKey, HMACKey)

# message = MyRSADecrypt(RSACipher, C, IV, tag, ext)
def MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_privatekey_filepath):
    private_key =  loadRSAKeyFile(RSA_privatekey_filepath, True)
    key = RSADecrypt(RSACipher, private_key)
    (encKey, HMACKey) = splitKey(key)



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
    MyRSADecrypt(RSACipher, C, IV, tag, ext, RSA_privatekey_filepath)

#test_RSAEncrypt()
#test_writeRSAKeyFile()
#test_loadRSAKeyFile()
test_MyRSAEncrypt()

#print(FileEncryption.getHMACKey())
#step1()