from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac
from Crypto import Random
from Crypto.Util import Padding
from hashlib import sha256

class TeaAESCipher():
    # https://gist.github.com/5S/4b9179e6b71fb9a74b9c30fca266d7d2
    def __init__(self, key: bytes, salt=None):
        self.__salt = salt
        if salt != None:
            self.__key = pbkdf2_hmac('sha256', key, self.__salt, 50000, int(128 / 8))
        else:
            # self.__key = (sha256(key.encode('utf-8')).hexdigest()).encode('utf-8')
            self.__key = key
    
    @classmethod
    def newsalt(cls, key):
        salt = Random.get_random_bytes(16)
        return cls(key, salt)

    @classmethod
    def new(cls, key):
        return cls(key)
    
    def get_salt(self):
        return self.__salt

    def encrypt(self, raw: bytes):
        iv = Random.get_random_bytes(AES.block_size)
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        data = Padding.pad(raw, AES.block_size, 'pkcs7')
        return iv + cipher.encrypt(data)

    def decrypt(self, data: bytes):
        iv = data[:AES.block_size]
        cipher = AES.new(self.__key, AES.MODE_CBC, iv)
        data = Padding.unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size, 'pkcs7')
        return data


class TeaECDHE():
    # https://telecom-engineer.blog/blog/2022/04/30/python-diffie-hellman
    def __init__(self) -> None:
        self.__prv_key = ec.generate_private_key(ec.SECP384R1())
        self.__pub_key = self.__prv_key.public_key()
    
    def __make_shared_key(self, public_key):
        shared_key = self.__prv_key.exchange(ec.ECDH(),public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'teasocket encryption',
        ).derive(shared_key)
        return derived_key
    
    def get_sharekey(self, pair_pubkey: str):
        pubkey = serialization.load_ssh_public_key(pair_pubkey.encode("utf8"))
        return self.__make_shared_key(pubkey)
    
    def get_pubkey(self):
        return self.__pub_key.public_bytes(encoding=serialization.Encoding.OpenSSH, format=serialization.PublicFormat.OpenSSH).decode("utf8")


if __name__ == '__main__':
    targetText = "test Text"
    a = TeaECDHE()
    b = TeaECDHE()
    pa = a.get_pubkey()
    pb = b.get_pubkey()
    print(pa, pb)
    
    sa = a.get_sharekey(pb)
    sb = b.get_sharekey(pa)
    print(sa)
    print(sb)
    
    a = TeaAESCipher.new(sa)
    s = a.get_salt()
    c = a.encrypt(targetText.encode("utf8"))
    print(c.hex())
    
    b = TeaAESCipher(sb, s)
    d = b.decrypt(c)
    print(d)