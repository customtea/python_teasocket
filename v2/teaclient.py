import socket
from enum import Enum
import sys

from getpass import getpass
from hashlib import sha256

__author__ = 'Github @customtea'
__version__ = '2.5.0'


CMDPREFIX = "\x11"


class ClientState(Enum):
    NOP = 0
    EXIT = 10
    TEXT = 20
    KEYWAIT = 30
    CMD = 40


class TeaClient():
    def __init__(self, ipaddr, port) -> None:
        self.__soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (ipaddr, port)
        self.__soc.connect(addr)
        self.__state = ClientState.NOP
        # print("Conection Established")
    
    def connect(self, debug=False):
        try:
            while self.__state != ClientState.EXIT:
                r_msg = self.__soc.recv(1024).decode('utf-8')
                msg = list(r_msg)
                while msg:
                    c = msg.pop(0)
                    if c == CMDPREFIX:
                        c1 = msg.pop(0)
                        c2 = msg.pop(0)
                        c3 = msg.pop(0)
                        cmd = c1 + c2 +c3
                        if debug:
                            print(f"CMD: {cmd}")
                        if cmd == "STX":
                            self.__state = ClientState.TEXT
                        elif cmd == "ETX":
                            self.__state = ClientState.NOP
                            sys.stdout.flush()
                        elif cmd == "FTX":
                            sys.stdout.flush()
                        elif cmd == "EDT":
                            self.__state = ClientState.EXIT
                        elif cmd == "KEY":
                            self.__state = ClientState.KEYWAIT
                            sys.stdout.flush()
                            while True:
                                sys.stdout.flush()
                                s_msg = input()
                                if s_msg != "":
                                    break
                            sys.stdout.flush()
                            self.__soc.sendall(s_msg.encode("utf8"))
                            self.__state = ClientState.NOP
                        elif cmd == "KSH":
                            self.__state = ClientState.KEYWAIT
                            while True:
                                sys.stdout.flush()
                                s_msg = input("> ")
                                if s_msg != "":
                                    break
                            sys.stdout.flush()
                            self.__soc.sendall(s_msg.encode("utf8"))
                            self.__state = ClientState.NOP
                        elif cmd == "KPS":
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
                        elif cmd == "SVC":
                            self.__state = ClientState.CMD
                        elif cmd == "EVC":
                            self.__state = ClientState.NOP
                    else:
                        if self.__state == ClientState.TEXT:
                            print(c, end="", flush=True) 
                        elif self.__state == ClientState.CMD:
                            ext_cmd += c

        except KeyboardInterrupt:
            pass
        finally:
            self.__soc.shutdown(socket.SHUT_RDWR)
            self.__soc.close()



def main(ipaddr, port_number):
    TC = TeaClient(ipaddr, port_number)
    TC.connect()


if __name__ == '__main__':
    main("127.0.0.1", 50000)