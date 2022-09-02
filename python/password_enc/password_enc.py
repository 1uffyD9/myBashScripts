#!/usr/bin/env python3

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from pathlib import Path
import binascii
import getpass
import sys


class CryptKeys:

    def __init__(self, pub_key: str, priv_key: str) -> None:
        self.pub_key_path = Path(pub_key).expanduser()
        self.prpriv_key_path = Path(priv_key).expanduser()


    def encrypt_text(self, clear_text: str) -> str:

        pub_key = ''
        ciphertext = ''
        tag = ''

        # get the pub key
        if self.pub_key_path.is_file():
            pub_key = RSA.import_key(open(self.pub_key_path).read())
        else:
            sys.exit("[!] [Error] Public key was not found! Please check the path and try again.")
            
        # generate a session key
        session_key = get_random_bytes(16)

        # Encrypt the session key with the public RSA key
        cipher_rsa = PKCS1_OAEP.new(pub_key)
        enc_session_key = cipher_rsa.encrypt(session_key)

        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)

        try:
            ciphertext, tag = cipher_aes.encrypt_and_digest(clear_text)
        except TypeError:
            ciphertext, tag = cipher_aes.encrypt_and_digest(clear_text.encode('utf-8'))

        return '.'.join([binascii.hexlify(x).decode("utf-8") for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)])


    def decrypt_cypher(self, cypher_text: str) -> str:

        private_key =""

        # get the pub key
        if self.prpriv_key_path.is_file():
            try:
                private_key = RSA.import_key(open(self.prpriv_key_path).read())

            except ValueError:
                try:
                    private_key = RSA.import_key(open(self.prpriv_key_path).read(), getpass.getpass("[>] Enter passphrase : "))
                except ValueError:
                    sys.exit("[!] [Error] Invalid Password!")

        else:
            sys.exit("[!] [Error] Private key was not found! Please check the path and try again.")

        
        enc_session_key, nonce, tag, ciphertext = [binascii.unhexlify(x) for x in cypher_text.split('.')]

        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        
        return data.decode("utf-8")


# ref : https://pycryptodome.readthedocs.io/en/latest/src/examples.html

data = "Hi, This is 1uffyD9".encode("utf-8")
pub_key_path = '~/.ssh/id_rsa1.pub'
priv_key_path = '~/.ssh/id_rsa1'

cp = CryptKeys(pub_key_path, priv_key_path)

# Encryption
cypher_t = cp.encrypt_text(data)
print(f"[!] Cypher text : {cypher_t}")

# Decryption
plain_t = cp.decrypt_cypher(cypher_t)
print(f"[*] Plain text : {plain_t}")
