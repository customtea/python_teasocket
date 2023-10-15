import socket
import threading
import typing
from enum import Enum

BUFSIZE = 1024
STARTCMD = b"\x11"
ENDCMD = b"\x12"

thread_mutex = threading.Lock()


class ClientCmd(Enum):
    TEXTBEG = STARTCMD + "textbeg".encode("utf8") + ENDCMD
    TEXTEND = STARTCMD + "textend".encode("utf8") + ENDCMD
    KEYWAIT = STARTCMD + "keywait".encode("utf8") + ENDCMD
    EXIT    = STARTCMD + "exit".encode("utf8") + ENDCMD


class TeaServer():
    def __init__(self, port) -> None:
        self.__soc_waiting = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = ("0.0.0.0", port)
        self.__soc_waiting.bind(addr)
        self.session = TeaSession
    
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

    def service(self): 
        pass



def main(port_number):
    TS = TeaServer(port_number)
    TS.up()



if __name__ == '__main__':
    main(50000)

