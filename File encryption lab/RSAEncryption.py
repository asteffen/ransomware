from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

PUBLIC_EXPONENT = 65537
KEY_SIZE_BITS = 2048
RSA_KEY_FILEPATH = "RSAKey.pem"

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

def loadRSAKeyFile(filepath):
    with open(filepath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    public_key = private_key.public_key()
    return (private_key, public_key)

def writeRSAKeyFile(filepath, private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filepath, "wb") as key_file:
        key_file.write(pem)

# (RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_filepath):
def MyRSAEncrypt(filepath, RSA_publickey_filepath):
    pass

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
    writeRSAKeyFile(RSA_KEY_FILEPATH, private_key)

#test_RSAEncrypt()
test_writeRSAKeyFile()

