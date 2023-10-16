import socket
from enum import Enum
import sys
import threading
import typing
from abc import abstractclassmethod

from getpass import getpass
from hashlib import sha256
from teaauth import TeaSecretKey, TeaPublicKey, randomstring
from teacrypto import TeaECDHE, TeaAESCipher

__author__ = 'Github @customtea'
__version__ = '5.5.0'


SEND_CMDPREFIX = b"\x11"
RECV_CMDPREFIX = "\x11"

BUFSIZE = 1024


class ClientState(Enum):
    NOP = 0
    CLOSE = 10
    TEXT = 20
    KEYWAIT = 30
    CMD = 40
    ENCRYPT = 90


class CtrlCode(Enum):
    HELLO       = "HLO"
    VERSION     = "VER"
    ACK         = "ACK"
    NAK         = "NAK"
    TEXTBEG     = "STX"
    TEXTEND     = "ETX"
    TEXTFLUSH   = "FTX"
    KEYWAIT     = "KEY"
    SHELLWAIT   = "KSH"
    PASSWAIT    = "KPS"
    AUTHWAIT    = "ATH"
    CMDBEG      = "SVC"
    CMDEND      = "EVC"
    KEYEXCHANGE = "KEX"
    PLAINMODE   = "PLN"
    ENCRYPTBEG  = "SCR"
    ENCRYPTEND  = "ECR"
    CLOSE       = "EDT"


class TeaSession():
    def __init__(self, soc: socket.socket) -> None:
        self.soc = soc
        self.is_encryption = False
    
    def _sendcmd(self, cmd: CtrlCode):
        self.send(SEND_CMDPREFIX + cmd.value.encode("utf8"))
    
    def _textbeg(self):
        self._sendcmd(CtrlCode.TEXTBEG)
    def _textend(self):
        self._sendcmd(CtrlCode.TEXTEND)

    def close(self):
        self._sendcmd(CtrlCode.CLOSE)
    
    def send(self, data: bytes):
        if self.is_encryption:
            self._encbeg()
            data = self.aes.encrypt(data).hex().encode("utf8")
            self.soc.sendall(data)
            self._encend()
        else:
            self.soc.sendall(data)
    
    def recv(self) -> bytes:
        data = self.soc.recv(BUFSIZE)
        if self.is_encryption:
            data = self.aes.decrypt(bytes.fromhex(data.decode("utf8")))
        return data

    def sendtext(self, text: str):
        self.send(text.encode("utf8"))

    def sendtextln(self, text: str):
        text = text + "\n"
        self.send(text.encode("utf8"))
    
    def print(self, *text, end="\n", sep=" "):
        self._textbeg()
        stext = sep.join(text) + end
        self.send(stext.encode("utf8"))
        self._textend()
    
    def keywait(self):
        self._sendcmd(CtrlCode.KEYWAIT)
        return self.recv().decode("utf8")

    def shellwait(self):
        self._sendcmd(CtrlCode.SHELLWAIT)
        return self.recv().decode("utf8")
    
    def passwait(self):
        self._sendcmd(CtrlCode.PASSWAIT)
        return self.recv().decode("utf8")

    def auth(self, publickey) -> bool:
        tpk = TeaPublicKey(publickey)
        org_cc, sig, res_cc = self.challnge()
        if org_cc == res_cc:
            return tpk.verify(sig, org_cc.encode("utf8"))
        return False

    def challnge(self) -> (str, str):
        challenge_code = randomstring(32)
        self._sendcmd(CtrlCode.AUTHWAIT)
        self.soc.sendall(challenge_code.encode("utf8"))
        rmsg = self.soc.recv(BUFSIZE).decode("utf8")
        sig, res_cc = rmsg.split(",")
        if challenge_code == res_cc:
            return challenge_code, sig, res_cc
    
    def keyexchange(self):
        self.session_ecdhe = TeaECDHE()
        pubkey = self.session_ecdhe.get_pubkey()
        self.soc.sendall(SEND_CMDPREFIX + CtrlCode.KEYEXCHANGE.value.encode("utf8"))
        self.soc.sendall(pubkey)
        rmsg = self.soc.recv(BUFSIZE)
        self.session_key = self.session_ecdhe.get_sharekey(rmsg)
        self.aes = TeaAESCipher.new(sha256(self.session_key).digest())
        self.is_encryption = True
    
    def plain_text(self):
        self._sendcmd(CtrlCode.PLAINMODE)
        self.is_encryption = False
    
    def _encbeg(self):
        self.soc.sendall(SEND_CMDPREFIX + CtrlCode.ENCRYPTBEG.value.encode("utf8"))

    def _encend(self):
        self.soc.sendall(SEND_CMDPREFIX + CtrlCode.ENCRYPTEND.value.encode("utf8"))
    
    @abstractclassmethod
    def service(self): 
        pass


class TeaServer():
    def __init__(self, port, session_class=TeaSession) -> None:
        self.__soc_waiting = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__soc_waiting.settimeout(0.5)
        addr = ("0.0.0.0", port)
        self.__soc_waiting.bind(addr)
        self.session = session_class
    
    def up(self):
        self.__soc_waiting.listen()
        self.__thread_list: typing.List[threading.Thread] = []
        while True:
            try:
                soc, fromaddr = self.__soc_waiting.accept()
                th = threading.Thread(target=self.__service, args=[soc])
                th.start()
                self.__thread_list.append(th)
            except socket.timeout:
                pass
            except KeyboardInterrupt:
                break

        for th in self.__thread_list:
            th.join()
        self.__soc_waiting.close()
    
    def __service(self, soc: socket.socket):
        msg = soc.recv(BUFSIZE).decode("utf8")
        msg = list(msg)
        stage = 0
        ver = ""
        while msg:
            c = msg.pop(0)
            if c == RECV_CMDPREFIX:
                c1 = msg.pop(0)
                c2 = msg.pop(0)
                c3 = msg.pop(0)
                cmd_text = c1 + c2 +c3
                cmd = CtrlCode(cmd_text)
                if cmd is CtrlCode.HELLO:
                    stage = 1
                elif cmd is CtrlCode.VERSION:
                    stage = 2
            else:
                if stage == 2:
                    ver += c
        if ver.split(".")[0] == __version__.split(".")[0]:
            stage = 3
        
        if stage == 3:
            soc.sendall(SEND_CMDPREFIX + CtrlCode.ACK.value.encode("utf8"))
            try:
                SS = self.session(soc)
                SS.service()
            except ConnectionResetError:
                return
            except BrokenPipeError:
                return
            except ConnectionAbortedError:
                return
        else:
            soc.sendall(SEND_CMDPREFIX + CtrlCode.CLOSE.value.encode("utf8"))



class TeaClient():
    def __init__(self, ipaddr, port) -> None:
        self.__soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (ipaddr, port)
        try:
            self.__soc.connect(addr)
        except ConnectionRefusedError:
            print("No Connection")
            exit(1)
        self.__state = ClientState.NOP
        self.__recv_enctyption = False
        self.__is_encryptionmode = False
        # print("Conection Established")
    
    def send(self, data: bytes):
        if self.__is_encryptionmode:
            data = self.__aes.encrypt(data).hex().encode("utf8")
        self.__soc.sendall(data)

    def recv(self) -> bytes:
        data = self.__soc.recv(BUFSIZE)
        return data

    def __sendcmd(self, cmd: CtrlCode):
        self.__soc.sendall(SEND_CMDPREFIX + cmd.value.encode("utf8"))
    
    def cmd_parse(self, cmd: CtrlCode):
        if cmd is CtrlCode.TEXTBEG:
            self.__state = ClientState.TEXT
            return

        if cmd is CtrlCode.TEXTEND:
            self.__state = ClientState.NOP
            sys.stdout.flush()
            return

        if cmd is CtrlCode.TEXTFLUSH:
            sys.stdout.flush()
            return

        if cmd is CtrlCode.CLOSE:
            self.__state = ClientState.CLOSE
            return

        if cmd is CtrlCode.KEYWAIT:
            self.__state = ClientState.KEYWAIT
            sys.stdout.flush()
            while True:
                s_msg = input()
                if s_msg != "":
                    break
            self.send(s_msg.encode("utf8"))
            self.__state = ClientState.NOP
            return

        if cmd is CtrlCode.SHELLWAIT:
            self.__state = ClientState.KEYWAIT
            while True:
                sys.stdout.flush()
                s_msg = input("> ")
                if s_msg != "":
                    break
            sys.stdout.flush()
            self.send(s_msg.encode("utf8"))
            self.__state = ClientState.NOP
            return

        if cmd is CtrlCode.PASSWAIT:
            self.__state = ClientState.KEYWAIT
            sys.stdout.flush()
            while True:
                sys.stdout.flush()
                prv_key = getpass()
                if prv_key != "":
                    break
            passwd_hash = sha256(prv_key.encode()).digest()
            self.send(passwd_hash)
            self.__state = ClientState.NOP
            return

        if cmd is CtrlCode.AUTHWAIT:
            self.__state = ClientState.KEYWAIT
            sys.stdout.flush()
            cc = self.recv()
            while True:
                sys.stdout.flush()
                prv_key = getpass()
                if prv_key != "":
                    break
            tsk = TeaSecretKey.password(prv_key)
            sig = tsk.sign(cc)
            s_msg = f"{sig},{cc.decode('utf8')}"
            self.__soc.sendall(s_msg.encode("utf8"))
            self.__state = ClientState.NOP
            return
        
        if cmd is CtrlCode.KEYEXCHANGE:
            self.__session_ecdhe = TeaECDHE()
            pubkey = self.__session_ecdhe.get_pubkey()
            rmsg = self.__soc.recv(BUFSIZE)
            self.__session_key = self.__session_ecdhe.get_sharekey(rmsg)
            self.__soc.sendall(pubkey)
            self.__aes = TeaAESCipher.new(sha256(self.__session_key).digest())
            self.__is_encryptionmode = True
            return
        
        if cmd is CtrlCode.ENCRYPTBEG:
            self.__recv_enctyption = True
            self.cip = ""
            return

        if cmd is CtrlCode.ENCRYPTEND:
            ltext = list(self.__aes.decrypt(bytes.fromhex(self.cip)).decode("utf8"))
            self.msg = ltext + self.msg
            self.__recv_enctyption = False
            return
        
        if cmd is CtrlCode.PLAINMODE:
            self.__is_encryptionmode = False

        if cmd is CtrlCode.CMDBEG:
            self.__state = ClientState.CMD
            self.ext_cmd = ""
            return

        if cmd is CtrlCode.CMDEND:
            self.ext_cmd_parse(self.ext_cmd)
            self.__state = ClientState.NOP
            return
    
    
    def ext_cmd_parse(self):
        pass

    
    def connect(self, debug=False):
        self.__sendcmd(CtrlCode.HELLO)
        self.__sendcmd(CtrlCode.VERSION)
        self.__soc.sendall(__version__.encode("utf8"))
        r_msg = self.__soc.recv(BUFSIZE).decode('utf-8')
        if r_msg != "\x11ACK":
            self.__state = ClientState.CLOSE
        self.ext_cmd = ""
        self.cip = ""
        self.__recv_enctyption = False
        try:
            while self.__state != ClientState.CLOSE:
                r_msg = self.recv().decode('utf-8')
                self.msg = list(r_msg)
                while self.msg:
                    c = self.msg.pop(0)
                    if c == RECV_CMDPREFIX:
                        c1 = self.msg.pop(0)
                        c2 = self.msg.pop(0)
                        c3 = self.msg.pop(0)
                        cmd_text = c1 + c2 +c3
                        if debug:
                            print(f"CMD: {cmd_text}", flush=True)
                        cmd = CtrlCode(cmd_text)
                        self.cmd_parse(cmd)
                    else:
                        if self.__recv_enctyption:
                            self.cip += c
                            continue
                        if self.__state is ClientState.TEXT:
                            print(c, end="", flush=True) 
                        elif self.__state is ClientState.CMD:
                            self.ext_cmd += c

        except KeyboardInterrupt:
            print("Abort")
        except ConnectionRefusedError:
            print("No Connection")
        finally:
            self.__soc.shutdown(socket.SHUT_RDWR)
            self.__soc.close()

