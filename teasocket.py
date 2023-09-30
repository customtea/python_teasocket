import socket
from enum import Enum
import sys
import threading
import typing
from abc import abstractclassmethod

from getpass import getpass
from hashlib import sha256

__author__ = 'Github @customtea'
__version__ = '3.1.0'


SEND_CMDPREFIX = b"\x11"
RECV_CMDPREFIX = "\x11"

BUFSIZE = 1024


class ClientState(Enum):
    NOP = 0
    CLOSE = 10
    TEXT = 20
    KEYWAIT = 30
    CMD = 40


class ClientCmd(Enum):
    TEXTBEG     = "STX"
    TEXTEND     = "ETX"
    TEXTFLUSH   = "FTX"
    KEYWAIT     = "KEY"
    SHELLWAIT   = "KSH"
    PASSWAIT    = "KPS"
    CMDBEG      = "SVC"
    CMDEND      = "EVC"
    CLOSE       = "EDT"


class TeaSession():
    def __init__(self, soc: socket.socket) -> None:
        self.soc = soc
    
    def _sendcmd(self, cmd: ClientCmd):
        self.soc.sendall(SEND_CMDPREFIX + cmd.value.encode("utf8"))
    
    def _textbeg(self):
        self._sendcmd(ClientCmd.TEXTBEG)
    def _textend(self):
        self._sendcmd(ClientCmd.TEXTEND)

    def close(self):
        self._sendcmd(ClientCmd.CLOSE)

    def sendtext(self, text: str):
        self.soc.sendall(text.encode("utf8"))

    def sendtextln(self, text: str):
        text = text + "\n"
        self.soc.sendall(text.encode("utf8"))
    
    def print(self, *text, end="\n", sep=" "):
        self._textbeg()
        stext = sep.join(text) + end
        self.soc.sendall(stext.encode("utf8"))
        self._textend()
    
    def keywait(self):
        self._sendcmd(ClientCmd.KEYWAIT)
        return self.soc.recv(BUFSIZE).decode("utf8")

    def shellwait(self):
        self._sendcmd(ClientCmd.SHELLWAIT)
        return self.soc.recv(BUFSIZE).decode("utf8")

    def passwait(self):
        self._sendcmd(ClientCmd.PASSWAIT)
        return self.soc.recv(BUFSIZE)
    
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
    
    def __service(self, soc):
        try:
            SS = self.session(soc)
            SS.service()
        except ConnectionResetError:
            return
        except BrokenPipeError:
            return
        except ConnectionAbortedError:
            return



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
        # print("Conection Established")
    
    def connect(self, debug=False):
        try:
            while self.__state != ClientState.CLOSE:
                r_msg = self.__soc.recv(BUFSIZE).decode('utf-8')
                msg = list(r_msg)
                while msg:
                    c = msg.pop(0)
                    if c == RECV_CMDPREFIX:
                        c1 = msg.pop(0)
                        c2 = msg.pop(0)
                        c3 = msg.pop(0)
                        cmd_text = c1 + c2 +c3
                        if debug:
                            print(f"CMD: {cmd_text}")
                        cmd = ClientCmd(cmd_text)

                        if cmd is ClientCmd.TEXTBEG:
                            self.__state = ClientState.TEXT

                        elif cmd is ClientCmd.TEXTEND:
                            self.__state = ClientState.NOP
                            sys.stdout.flush()

                        elif cmd is ClientCmd.TEXTFLUSH:
                            sys.stdout.flush()

                        elif cmd is ClientCmd.CLOSE:
                            self.__state = ClientState.CLOSE

                        elif cmd is ClientCmd.KEYWAIT:
                            self.__state = ClientState.KEYWAIT
                            sys.stdout.flush()
                            while True:
                                s_msg = input()
                                if s_msg != "":
                                    break
                            self.__soc.sendall(s_msg.encode("utf8"))
                            self.__state = ClientState.NOP

                        elif cmd is ClientCmd.SHELLWAIT:
                            self.__state = ClientState.KEYWAIT
                            while True:
                                sys.stdout.flush()
                                s_msg = input("> ")
                                if s_msg != "":
                                    break
                            sys.stdout.flush()
                            self.__soc.sendall(s_msg.encode("utf8"))
                            self.__state = ClientState.NOP

                        elif cmd is ClientCmd.PASSWAIT:
                            self.__state = ClientState.KEYWAIT
                            sys.stdout.flush()
                            while True:
                                sys.stdout.flush()
                                passwd_plain = getpass()
                                if passwd_plain != "":
                                    break
                            passwd_hash = sha256(passwd_plain.encode()).digest()
                            self.__soc.sendall(passwd_hash)
                            self.__state = ClientState.NOP

                        elif cmd is ClientCmd.CMDBEG:
                            self.__state = ClientState.CMD

                        elif cmd is ClientCmd.CMDEND:
                            self.__state = ClientState.NOP

                    else:
                        if self.__state == ClientState.TEXT:
                            print(c, end="", flush=True) 
                        elif self.__state == ClientState.CMD:
                            ext_cmd += c

        except KeyboardInterrupt:
            print("Abort")
        except ConnectionRefusedError:
            print("No Connection")
        finally:
            self.__soc.shutdown(socket.SHUT_RDWR)
            self.__soc.close()

