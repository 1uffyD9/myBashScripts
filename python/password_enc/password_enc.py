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
        # validate the pub key
        if not self.pub_key_path.is_file():
            sys.exit("[!] FileNotFoundError: Public key was not found! Please check the path and try again.")

        # validate the priv key
        if not self.prpriv_key_path.is_file():
            sys.exit("[!] FileNotFoundError: Private key was not found! Please check the path and try again.")
        

    def encrypt_text(self, clear_text: str) -> str:

        pub_key = ''
        ciphertext = ''
        tag = ''

        pub_key = RSA.import_key(open(self.pub_key_path).read())
            
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
        except Exception as e:
            sys.exit(f"Public key error: {e}")

        return '.'.join([binascii.hexlify(x).decode("utf-8") for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)])


    def decrypt_cypher(self, cypher_text: str, key_pass: str = None) -> str:

        private_key = ""

        try:
            # get the pub key
            try:
                private_key = RSA.import_key(open(self.prpriv_key_path).read())
            except ValueError:
                if key_pass:
                    private_key = RSA.import_key(open(self.prpriv_key_path).read(), key_pass)
                else:
                    private_key = RSA.import_key(open(self.prpriv_key_path).read(), getpass.getpass("[>] Enter passphrase (RSA): "))
        except ValueError:
            sys.exit("[!] RSA Error: Incorrect password for RSA keys")

        enc_session_key, nonce, tag, ciphertext = [binascii.unhexlify(x) for x in cypher_text.split('.')]

        try:
            # Decrypt the session key with the private RSA key
            cipher_rsa = PKCS1_OAEP.new(private_key)
            session_key = cipher_rsa.decrypt(enc_session_key)

            # Decrypt the data with the AES session key
            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        except Exception as e:
            sys.exit(f"Private key error: {e}")
        
        return data.decode("utf-8")


# ref : https://pycryptodome.readthedocs.io/en/latest/src/examples.html

data = "Hi, This is 1uffyD9".encode("utf-8")
pub_key_path = '~/.ssh/id_rsa1.pub'
priv_key_path = '~/.ssh/id_rsa1'

cp = CryptKeys(pub_key_path, priv_key_path)

# Encryption
cypher_t = cp.encrypt_text(data)
print(f"[!] Cypher text : {cypher_t}")

# Decryption with user input
plain_t = cp.decrypt_cypher(cypher_t)
print(f"[*] Plain text : {plain_t}")

# Decryption without user input
plain_t = cp.decrypt_cypher(cypher_t, "password_here")
print(f"[*] Plain text : {plain_t}")
