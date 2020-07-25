# Ransomware Demo

This program encrypts the files in a test directory  using AES-256. Then, the AES key is encrypted with RSA encryption. The private key is posted to a secure server running in AWS Cloud, and stored in a MongoDB database.

### Encrypting
* To encrypt files in the test directory, run `RSAEncryptionExe.py`
* This file generates new keys, posts them to the server, encrypts the directory, then deletes the private key.

### Decrypting
* To decrypt files in the test directory, run `RSADecryptionExe.py`
* This file retrieves the private key from the server, decrypts the directory, then deletes the private key.