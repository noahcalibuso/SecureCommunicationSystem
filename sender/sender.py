from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256
from Crypto.Util.Padding import pad
from base64 import b64encode
import json

"""
    AES Session Key and RSA Public/Private Key Generation
"""
# Generate new RSA Private Key
key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("sender_private_key.pem", "wb")
file_out.write(private_key)
file_out.close()

# Generate the RSA Public Key
public_key = key.publickey().export_key()
file_out = open("../transmitted_data/sender_public_key.pem", "wb")
file_out.write(public_key)
file_out.close()
print("Sender's Private/Public Key pair generated\n")

pt = input("Message to receiver: ")
file_out = open("sender_message.txt", "w")
file_out.write(pt)
file_out.close()

# Generate new AES session key
session_key = get_random_bytes(16)
print("\nSession key generated")

# Generate Hashed Message Authentication Code (HMAC)
h = HMAC.new(session_key, digestmod=SHA256)

"""
    Encryption
"""
# Read in and encrypt sender's plaintext message using session key
msg = open("sender_message.txt", "rb").read()
aes_cipher = AES.new(session_key, AES.MODE_CBC)
ciphertext = aes_cipher.encrypt(pad(msg, AES.block_size))
print("Sender's message encrypted using session key")

# Encrypt the session key with receiver's public RSA key
receiver_public_key = RSA.import_key(open("../transmitted_data/receiver_public_key.pem").read())
rsa_cipher = PKCS1_OAEP.new(receiver_public_key)
enc_session_key = rsa_cipher.encrypt(session_key)
print("Session key encrypted using receiver's public key")

# get HMAC of the ecnrypted message (Ecrypt-then-MAC)
h.update(ciphertext)
print("Message Authentication Code (HMAC) of ciphertext generated")

# JSONify the data
esk = b64encode(enc_session_key).decode('utf-8')
ct = b64encode(ciphertext).decode('utf-8')
iv = b64encode(aes_cipher.iv).decode('utf-8')
mac = b64encode(h.digest()).decode('utf-8')
x = json.dumps({'esk': esk, 'ct': ct, 'iv': iv, 'mac': mac})
print("Encrypted Session Key, Ciphertext, Initialization Vector, and MAC appended to message\n")

# "transmit" the:
#       encrypted session key (encrypted with receiver's public key)
#       sender's message (encrypted with session key)
#       iv (Initialization Vector)
#       HMAC of ciphertext
file_out = open("../transmitted_data/encrypted_data.bin", "w")
file_out.write(x)
file_out.close()
print("Message has been sent!")
