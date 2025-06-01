#doc: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
#doc: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.exceptions import InvalidKey 
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64

class Crypt:
    def __init__(self):
        pass

    def generate_salt(self):
        return os.urandom(16)
    
    def derive_key_from_passwd(self,passwd,salt):
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_000_000,
        )
        key = kdf.derive(passwd.encode("utf-8"))
        return key
    
    def encrypt(self,textPlain,key):
        try:
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
            encryptor = cipher.encryptor()
        
            padded_data = self._padding(textPlain)
            ct = encryptor.update(padded_data) + encryptor.finalize()
            return ct,iv
        except:
            return None,None

    def decrypt(self,textEncrypt,key,iv):
        try:
            cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
            decryptor = cipher.decryptor()
            text_plain_padded = decryptor.update(textEncrypt) + decryptor.finalize()
            text_plain_unpadded = self._unpadding(text_plain_padded)
            return text_plain_unpadded
        except (ValueError, InvalidKey):
            return None


    def _padding(self,data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode("utf-8")) + padder.finalize()
        return padded_data
    def _unpadding(self,data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data.decode()
    def base64_encode(self,data_bytes):
        data_base64 = base64.b64encode(data_bytes).decode("ascii")
        return data_base64
    
    def base64_decode(self,str_base64):
        data_binary = base64.b64decode(str_base64.encode("ascii"))
        return data_binary
    
    