from teaserver import TeaServer, TeaSession

class TestSession(TeaSession):
    def service(self):
        self.print("Welcome")
        # self.print("login: ", end="")
        # user = self.keywait()
        # print(user)
        # authres = self.auth("c4db4fd18c68690d10e100a9077d08ca722116ef39896a63b9eae5dd4f8aebfa")
        # if authres:
        #     self.print("Success")
        # else:
        #     self.print("Incorrect User")
        
        self.print("Start KeyExchange test")
        self.keyexchange()
        self.print("Important Things")
        user = self.keywait("login: ")
        print(user)
        authres = self.auth("c4db4fd18c68690d10e100a9077d08ca722116ef39896a63b9eae5dd4f8aebfa")
        if authres:
            self.print("Success")
        else:
            self.print("Incorrect User")
        self.close()

def main(port_number):
    TS = TeaServer(port_number, TestSession)
    print("Server Up")
    TS.up()



if __name__ == '__main__':
    main(50000)

