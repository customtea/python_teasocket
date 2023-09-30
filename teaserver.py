from teasocket import TeaServer, TeaSession

class TestSession(TeaSession):
    def service(self):
        print(self.soc)
        self.print("Welcome")
        self.print("login: ", end="")
        text = self.keywait()
        print(text)
        self.print()
        self.close()


def main(port_number):
    TS = TeaServer(port_number, TestSession)
    TS.up()



if __name__ == '__main__':
    main(50000)

