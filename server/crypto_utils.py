import os
from base64 import b64decode, b64encode

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.PublicKey import RSA


def generate_aes_key():
    return b64encode(os.urandom(16)).decode("utf-8")


def rsa_encrypt(public_key, plain_text):
    der = b64decode(public_key)
    rsa_key = RSA.importKey(der)
    rsa_cipher = Cipher_PKCS1_v1_5.new(rsa_key)
    result = rsa_cipher.encrypt(plain_text.encode("utf-8"))
    return b64encode(result)


def aes_decrypt(encoded_aes_key, cipher_text):
    aes_key = b64decode(encoded_aes_key)
    iv = AES.block_size * b'\x00'
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return cipher.decrypt(b64decode(cipher_text))
