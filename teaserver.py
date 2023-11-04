import socket
from hashlib import sha256
import threading
import typing
from abc import abstractclassmethod

from teapacket import TeaPacket, BUFSIZE, CtrlType, __version__, __author__
from teaauth import randomstring, TeaPublicKey
from teacrypto import TeaAESCipher, TeaECDHE

class TeaSession():
    def __init__(self, soc: socket.socket) -> None:
        self.__soc = soc
        self.__is_encryption = False
        self.__recv_data: list[chr] = []
        self.__msg = ""
        self.__braket_count = 0

    def send(self, data: bytes):
        if self.__is_encryption:
            data = self.aes.encrypt(data).hex()
            self.__soc.sendall(TeaPacket.encrypt(data))
        else:
            self.__soc.sendall(data)
    
    def recv(self) -> TeaPacket:
        while True:
            if not self.__recv_data:
                self.__recv_data += list(self.__soc.recv(BUFSIZE).decode("utf8"))
            while self.__recv_data:
                c = self.__recv_data.pop(0)
                if c == "{":
                    self.__braket_count += 1
                elif c == "}":
                    self.__braket_count -= 1
                self.__msg += c
                if self.__braket_count == 0:
                    msgp = TeaPacket.parse(self.__msg)
                    self.__msg = ""
                    break
            if self.__braket_count != 0:
                continue

            # print("DEBUG", msgp, flush=True)

            if msgp.is_msgtype(CtrlType.ENCRYPT):
                data = self.aes.decrypt(bytes.fromhex(msgp.content))
                msgp = TeaPacket.parse(data)
            return msgp

    def close(self):
        self.send(TeaPacket.close())

    def sendtext(self, text: str):
        self.send(TeaPacket.text(text))

    def sendtextln(self, text: str):
        text = text + "\n"
        self.send(TeaPacket.text(text))
    
    def print(self, *text, end="\n", sep=" "):
        stext = sep.join(text) + end
        self.send(TeaPacket.text(stext))
    
    def keywait(self, prompt=""):
        self.send(TeaPacket.keyreq(prompt=prompt))
        pkt = self.recv()
        return pkt.content

    def shellwait(self):
        self.send(TeaPacket.keyreq(prompt="> "))
        pkt = self.recv()
        return pkt.content
    
    def passwait(self):
        self.send(TeaPacket.passreq())
        pkt = self.recv()
        return pkt.content

    def auth(self, publickey) -> bool:
        tpk = TeaPublicKey(publickey)
        org_cc, sig, res_cc = self.challnge()
        if org_cc == res_cc:
            return tpk.verify(sig, org_cc.encode("utf8"))
        return False

    def challnge(self) -> (str, str):
        challenge_code = randomstring(32)
        self.send(TeaPacket.authreq(challenge_code))
        rpacket = self.recv()
        sig = rpacket.content["sig"]
        res_cc = rpacket.content["ccode"]
        if challenge_code == res_cc:
            return challenge_code, sig, res_cc
    
    def keyexchange(self):
        self.session_ecdhe = TeaECDHE()
        pubkey = self.session_ecdhe.get_pubkey()
        self.__soc.sendall(TeaPacket.keyexchange(pubkey))
        rpacket = self.recv()
        self.session_key = self.session_ecdhe.get_sharekey(rpacket.content)
        self.aes = TeaAESCipher.new(sha256(self.session_key).digest())
        self.__is_encryption = True
    
    @abstractclassmethod
    def service(self): 
        pass


def recv_teapacket(soc, recv_data, braket_count) -> TeaPacket:
    msg = ""
    while True:
        if not recv_data:
            recv_data += list(soc.recv(BUFSIZE).decode("utf8"))
        while recv_data:
            c = recv_data.pop(0)
            if c == "{":
                braket_count += 1
            elif c == "}":
                braket_count -= 1
            msg += c
            if braket_count == 0:
                msgp = TeaPacket.parse(msg)
                msg = ""
                break
        if braket_count != 0:
            continue
        return msgp

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
        braket_count = 0
        recv_data = []
        rpkt = recv_teapacket(soc, recv_data, braket_count)
        if not rpkt.is_msgtype(CtrlType.HELLO):
            soc.sendall(TeaPacket.close())
            return
        ver = rpkt.content["version"]
        if ver.split(".")[0] != __version__.split(".")[0]:
            soc.sendall(TeaPacket.close())
            return
        soc.sendall(TeaPacket.ack())
        try:
            SS = self.session(soc)
            SS.__recv_data = recv_data
            SS.__braket_count = braket_count
            SS.service()
        except ConnectionResetError:
            return
        except BrokenPipeError:
            return
        except ConnectionAbortedError:
            return

