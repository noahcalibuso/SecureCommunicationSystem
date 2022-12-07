import sys
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
import json
from base64 import b64decode
from Crypto.Util.Padding import unpad

"""
    AES Session Key and RSA Public/Private Key Generation
"""
# Generate new RSA Private Key
key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("receiver_private_key.pem", "wb")
file_out.write(private_key)
file_out.close()

# Generate the RSA Public Key
public_key = key.publickey().export_key()
file_out = open("../transmitted_data/receiver_public_key.pem", "wb")
file_out.write(public_key)
file_out.close()
print("Receiver's Private/Public Key pair generated")

print("Public Key has been sent to the sender!")
input("Press Enter once sender has sent the message...")

# Parse the received message (json object)
file_in = json.loads(open("../transmitted_data/encrypted_data.bin", "r").read())
enc_session_key = b64decode(file_in['esk'].encode('utf-8'))
ciphertext = b64decode(file_in['ct'])
iv = b64decode(file_in['iv'])
mac = b64decode(file_in['mac'])

# Decrypt the session key with receiver's private RSA key
try:
    pk = RSA.import_key(open("receiver_private_key.pem").read())
    rsa_cipher = PKCS1_OAEP.new(pk)
    session_key = rsa_cipher.decrypt(enc_session_key)
    print("Message received!")
except (ValueError, KeyError):
    print("No message received or Incorrect decryption")
    sys.exit()

# Validate the MAC,
# if the mac is invalid the receiver does not attempt to decrypt the ciphertext
print("Validating the MAC...")
h = HMAC.new(session_key, digestmod=SHA256)
h.update(ciphertext)
try:
    h.verify(mac)
    print("The message is valid")
except ValueError:
    print("The message is invalid")
    sys.exit()

# Decrypt the ciphertext using the decrypted AES session key
print("Decrypting the ciphertext using the session key...")
try:
    aes_cipher = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = unpad(aes_cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    print("The message is: ", plaintext)
except (ValueError, KeyError):
    print("Decryption error")
