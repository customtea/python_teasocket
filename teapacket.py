from enum import Enum
import json
import typing

__author__ = 'https://github.com/customtea/'
__version__ = '6.1.0'

BUFSIZE = 4096


class CtrlType(Enum):
    HELLO       = "HLO"
    VERSION     = "VER"
    ACK         = "ACK"
    NAK         = "NAK"
    TEXT        = "TXT"
    TEXTFLUSH   = "FTX"
    KEYREQ      = "QKY"
    KEYRES      = "RKY"
    PASSREQ     = "QPS"
    PASSRES     = "RPS"
    AUTHREQ     = "QAU"
    AUTHRES     = "RAU"
    KEYEXCHANGE = "KEX"
    ENCRYPT     = "ENC"
    CLOSE       = "EDT"
    RXTHREAD    = "RXT"


class TeaPacket():
    def __init__(self, ctrl_type: CtrlType, **kwargs) -> None:
        self.msgtype = ctrl_type
        self.content = kwargs
    
    def __str__(self) -> str:
        return json.dumps({"type": self.msgtype.name, "content":self.content}, indent=4)
        # return f"TYPE:{self.msgtype}, CONTENT:{self.content}"
    
    def get_msgtype(self):
        return self.msgtype
    
    def is_msgtype(self, typ: CtrlType):
        return self.msgtype == typ
    
    @classmethod
    def parse(cls, text: str):
        d = json.loads(text)
        c = cls(CtrlType.ACK)
        c.msgtype = CtrlType[d["type"]]
        if "content" in d:
            c.content = d["content"]
        return c
    
    def encode(self) -> bytes:
        if self.content == "" or self.content == [] or self.content == {} or self.content == None:
            d = { "type": self.msgtype.name }
        else:
            d = { "type": self.msgtype.name, "content" : self.content }
        return json.dumps(d).encode("utf8")
    
    @classmethod
    def encrypt(cls, data: str):
        c = cls(CtrlType.ENCRYPT)
        c.content = data
        return c.encode()
    
    @classmethod
    def text(cls, msg):
        c = cls(CtrlType.TEXT)
        c.content = msg
        return c.encode()
    
    @classmethod
    def keyreq(cls, prompt=""):
        c = cls(CtrlType.KEYREQ)
        c.content = prompt
        return c.encode()

    @classmethod
    def keyres(cls, key):
        c = cls(CtrlType.KEYRES)
        c.content = key
        return c.encode()

    @classmethod
    def passreq(cls):
        c = cls(CtrlType.PASSREQ)
        return c.encode()

    @classmethod
    def passres(cls, passwd):
        c = cls(CtrlType.PASSRES)
        c.content = passwd
        return c.encode()

    @classmethod
    def authreq(cls, challenge_code):
        c = cls(CtrlType.AUTHREQ)
        c.content = challenge_code
        return c.encode()
        
    @classmethod
    def authres(cls, challenge_code, signature):
        c = cls(CtrlType.AUTHRES)
        c.content = {
            "ccode": challenge_code,
            "sig" : signature
        }
        return c.encode()
    
    @classmethod
    def keyexchange(cls, pubkey):
        c = cls(CtrlType.KEYEXCHANGE)
        c.content = pubkey
        return c.encode()
    
    @classmethod
    def hello(cls):
        c = cls(CtrlType.HELLO)
        return c.encode()

    @classmethod
    def ack(cls):
        c = cls(CtrlType.ACK)
        return c.encode()

    @classmethod
    def nak(cls):
        c = cls(CtrlType.NAK)
        return c.encode()
    
    @classmethod
    def close(cls):
        c = cls(CtrlType.CLOSE)
        return c.encode()


