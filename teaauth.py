# inspired FIDO2

__author__ = 'https://github.com/customtea/'
__version__ = '1.1.0'

from ecdsa import Ed25519, SigningKey, VerifyingKey, BadSignatureError
from hashlib import sha256
import random, string

def randomstring(n):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

class TeaSecretKey():
    def __init__(self, prvhexkey) -> None:
        self.__prv_key = SigningKey.from_string(bytes.fromhex(prvhexkey), curve=Ed25519)
        self.__pub_key = self.__prv_key.get_verifying_key()
    
    @classmethod
    def password(cls, password: str):
        return cls(sha256(password.encode("utf8")).digest().hex())

    @classmethod
    def file(cls, filename: str):
        with open(filename) as f:
            return cls(f.read())
    
    def get_publickey(self):
        return self.__pub_key.to_string().hex()
    
    def sign(self, data: bytes):
        return self.__prv_key.sign(data).hex()


class TeaPublicKey():
    def __init__(self, pubhexkey) -> None:
        self.__pub_key = VerifyingKey.from_string(bytes.fromhex(pubhexkey), curve=Ed25519)
        self.__challenge_code = None

    def get_publickey(self):
        return self.__pub_key.to_string().hex()
    
    def challenge(self):
        self.__challenge_code = randomstring(32)
        return self.__challenge_code
    
    def challenge_verify(self, signature):
        return self.verify(signature, self.__challenge_code.encode("utf8"))
    
    def verify(self, signature, data):
        try: 
            return self.__pub_key.verify(bytes.fromhex(signature), data)
        except BadSignatureError:
            return False


if __name__ == '__main__':
    ts = TeaSecretKey.password("abcdef")
    print(ts.get_publickey())
    tp = TeaPublicKey(ts.get_publickey())

    tt = "Challenge".encode("utf8")
    print(ts.sign(tt))
    print(tp.verify(ts.sign(tt), tt))
