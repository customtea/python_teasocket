import socket
from enum import Enum


STARTCMD = "\x11"
ENDCMD = "\x12"


class ClientState(Enum):
    NOP = 0
    EXIT = 10
    TEXT = 20
    KEYWAIT = 30


class TeaClient():
    def __init__(self, ipaddr, port) -> None:
        self.__soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        addr = (ipaddr, port)
        self.__soc.connect(addr)
        # print("Conection Established")
        self.__state = ClientState.NOP
    
    def connect(self):
        try:
            while self.__state != ClientState.EXIT:
                r_msg = self.__soc.recv(1024).decode('utf-8')
                # print(f"RAW: ### {r_msg} ###")
                msgs = r_msg.split(STARTCMD)
                # print(msgs)
                while msgs:
                    msg = msgs.pop(0)
                    if msg == "":
                        continue
                    # print(f"MSG: {msg}")
                    if ENDCMD in msg:
                        stc = 0
                        # stc = msg.find(STARTCMD)
                        edc = msg.find(ENDCMD)
                        client_cmd = msg[stc: edc]
                        # print(f"CMD: {client_cmd}")

                        if "textbeg" in client_cmd:
                            self.__state = ClientState.TEXT
                        elif "textend" in client_cmd:
                            self.__state = ClientState.NOP
                            continue
                        elif "keywait"  in client_cmd:
                            self.__state == ClientState.KEYWAIT
                            s_msg = input("> ")
                            self.__soc.sendall(s_msg.encode("utf8"))
                            self.__state == ClientState.NOP
                        elif "exit" in client_cmd:
                            self.__state = ClientState.EXIT
                            print("Connection Closed")
                        continue

                    if self.__state == ClientState.NOP:
                        continue
                    elif self.__state == ClientState.TEXT:
                        print(msg)

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