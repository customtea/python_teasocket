from teaclient import TeaClient

def main(ipaddr, port_number):
    TC = TeaClient(ipaddr, port_number)
    TC.connect()


if __name__ == '__main__':
    main("127.0.0.1", 50000)
