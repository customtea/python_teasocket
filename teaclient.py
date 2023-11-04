import socket
from getpass import getpass
from hashlib import sha256
import sys
import typing
import threading

from teapacket import TeaPacket, BUFSIZE, CtrlType, __author__, __version__
from teaauth import TeaSecretKey
from teacrypto import TeaAESCipher, TeaECDHE

class TeaClient():
    def __init__(self, ipaddr, port) -> None:
        self.__soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (ipaddr, port)
        try:
            self.__soc.connect(addr)
        except ConnectionRefusedError:
            print("No Connection")
            exit(1)
        self.__is_running = True
        self.__is_encryptionmode = False
        self.__recv_data: list[chr] = []
        self.__breaket_count = 0
        self.__msg = ""
        # print("Conection Established")
    
    def send(self, data: bytes):
        if self.__is_encryptionmode:
            data = self.__aes.encrypt(data).hex()
            data = TeaPacket.encrypt(data)
        self.__soc.sendall(data)

    def recv(self) -> TeaPacket:
        while True:
            if not self.__recv_data:
                self.__recv_data += list(self.__soc.recv(BUFSIZE).decode("utf8"))
            while self.__recv_data:
                c = self.__recv_data.pop(0)
                if c == "{":
                    self.__breaket_count += 1
                elif c == "}":
                    self.__breaket_count -= 1
                self.__msg += c
                if self.__breaket_count == 0:
                    pkt = TeaPacket.parse(self.__msg)
                    self.__msg = ""
                    break

            if self.__breaket_count != 0:
                continue

            if pkt.is_msgtype(CtrlType.ENCRYPT):
                data = self.__aes.decrypt(bytes.fromhex(pkt.content))
                pkt = TeaPacket.parse(data)
            return pkt

    
    def act(self, pkt: TeaPacket):
        msgtype = pkt.get_msgtype()
        if msgtype is CtrlType.TEXT:
            print(pkt.content, end="")
            return

        if msgtype is CtrlType.TEXTFLUSH:
            sys.stdout.flush()
            return

        if msgtype is CtrlType.CLOSE:
            self.__is_running = False
            return

        if msgtype is CtrlType.KEYREQ:
            while True:
                if not pkt.content:
                    prompt = ""
                else:
                    prompt = pkt.content
                s_msg = input(prompt)
                if s_msg != "":
                    break
            self.send(TeaPacket.keyres(s_msg))
            return

        if msgtype is CtrlType.PASSREQ:
            while True:
                prv_key = getpass()
                if prv_key != "":
                    break
            passwd_hash = sha256(prv_key.encode()).digest()
            self.send(TeaPacket.passres(passwd_hash))
            return

        if msgtype is CtrlType.AUTHREQ:
            cc = pkt.content
            while True:
                prv_key = getpass()
                if prv_key != "":
                    break
            tsk = TeaSecretKey.password(prv_key)
            sig = tsk.sign(cc.encode("utf8"))
            self.send(TeaPacket.authres(cc, sig))
            return
        
        if msgtype is CtrlType.KEYEXCHANGE:
            self.__session_ecdhe = TeaECDHE()
            pubkey = self.__session_ecdhe.get_pubkey()
            serv_pubkey = pkt.content
            self.__session_key = self.__session_ecdhe.get_sharekey(serv_pubkey)
            self.__soc.sendall(TeaPacket.keyexchange(pubkey))
            self.__aes = TeaAESCipher.new(sha256(self.__session_key).digest())
            self.__is_encryptionmode = True
            return
        
    
    def connect(self, debug=False):
        # debug = True
        try:
            spkt = TeaPacket(CtrlType.HELLO)
            spkt.content = {
                "author": __author__,
                "version": __version__
            }
            self.send(spkt.encode())
            rpkt = self.recv()
            if not rpkt.is_msgtype(CtrlType.ACK):
                raise ConnectionAbortedError
            while self.__is_running:
                rpacket = self.recv()
                if debug:
                    print("====DEBUG====")
                    print(rpacket)
                    print("=============")
                self.act(rpacket)

        except KeyboardInterrupt:
            self.send(TeaPacket.close())
            print("Abort")
        except ConnectionRefusedError:
            print("No Connection")
        except ConnectionAbortedError:
            print("Abort")
        finally:
            self.__soc.shutdown(socket.SHUT_RDWR)
            self.__soc.close()