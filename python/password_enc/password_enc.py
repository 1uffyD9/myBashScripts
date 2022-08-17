from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from pathlib import Path
import binascii
import getpass
import sys


class CryptKeys:

    def encrypt_text(self, key_file: str, clear_text: str) -> str:

        pub_key = ""

        # get the pub key
        if Path(key_file).expanduser().is_file():
            pub_key = RSA.import_key(open(key_file).read())
        else:
            sys.exit("[!] Key was not found! Please check the path and try again.")
            
        # generate a session key
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(clear_text)

        return '.'.join([binascii.hexlify(x).decode("utf-8") for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)])


    def decrypt_cypher(self, key_file:str, cypher_text: str) -> str:

        private_key =""

        # get the pub key
        if Path(key_file).expanduser().is_file():
            try:
                private_key = RSA.import_key(open(key_file).read())

            except ValueError:
                private_key = RSA.import_key(open(key_file).read(), getpass.getpass("Enter passphrase : "))

        else:
            sys.exit("[!] Key was not found! Please check the path and try again.")

        
        enc_session_key, nonce, tag, ciphertext = [binascii.unhexlify(x) for x in cypher_text.split('.')]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        
        return data.decode("utf-8")



cp = CryptKeys()
pub_key_path = 'testkey.pub'
priv_key_path = 'testkey.pem'

data = "I met aliens in UFO. Here is the map.".encode("utf-8")
cypher_t = cp.encrypt_text(pub_key_path, data)
plain_t = cp.decrypt_cypher(priv_key_path, cypher_t)

print(plain_t)
