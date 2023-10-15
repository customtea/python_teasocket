import socket
import threading
import typing
from enum import Enum
from abc import abstractclassmethod

__author__ = 'Github @customtea'
__version__ = '2.5.0'

BUFSIZE = 1024
CMDPREFIX = b"\x11"

thread_mutex = threading.Lock()


class ClientCmd(Enum):
    TEXTBEG     = CMDPREFIX + "STX".encode("utf8")
    TEXTEND     = CMDPREFIX + "ETX".encode("utf8")
    TEXTFLUSH   = CMDPREFIX + "FTX".encode("utf8")
    KEYWAIT     = CMDPREFIX + "KEY".encode("utf8")
    SHELLWAIT   = CMDPREFIX + "KSH".encode("utf8")
    PASSWAIT    = CMDPREFIX + "KPS".encode("utf8")
    CMDBEG      = CMDPREFIX + "SVC".encode("utf8")
    CMDEND      = CMDPREFIX + "EVC".encode("utf8")
    EXIT        = CMDPREFIX + "EDT".encode("utf8")



class TeaSession():
    def __init__(self, soc: socket.socket) -> None:
        self.soc = soc
    
    def _textbeg(self):
        self.soc.sendall(ClientCmd.TEXTBEG.value)
    def _textend(self):
        self.soc.sendall(ClientCmd.TEXTEND.value)
    def _keywait(self):
        self.soc.sendall(ClientCmd.KEYWAIT.value)
    def _exit(self):
        self.soc.sendall(ClientCmd.EXIT.value)

    def send_one_text(self, text: str):
        self._textbeg()
        self.soc.sendall(text.encode("utf8"))
        self._textend()

    def send_one_textln(self, text: str):
        self._textbeg()
        text = text + "\n"
        self.soc.sendall(text.encode("utf8"))
        self._textend()
    
    def sendtext(self, text: str):
        self.soc.sendall(text.encode("utf8"))

    def sendtextln(self, text: str):
        text = text + "\n"
        self.soc.sendall(text.encode("utf8"))
    
    def print(self, text, end="\n"):
        self._textbeg()
        text = text + end
        self.soc.sendall(text.encode("utf8"))
        self._textend()
    
    def keywait(self):
        self._keywait()
        return self.soc.recv(BUFSIZE).decode("utf8")

    def shellwait(self):
        self.soc.sendall(ClientCmd.SHELLWAIT.value)
        return self.soc.recv(BUFSIZE).decode("utf8")

    def passwait(self):
        self.soc.sendall(ClientCmd.PASSWAIT.value)
        return self.soc.recv(BUFSIZE)
    
    @abstractclassmethod
    def service(self): 
        pass


class TeaServer():
    def __init__(self, port, session_class=TeaSession) -> None:
        self.__soc_waiting = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        except KeyboardInterrupt:
            return


class TestSession(TeaSession):
    def service(self):
        print(self.soc)
        self.print("Welcome")
        self.print("login: ", end="")
        text = self.keywait()
        print(text)
        self._exit()


def main(port_number):
    TS = TeaServer(port_number, TestSession)
    TS.up()



if __name__ == '__main__':
    main(50000)

