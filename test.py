from teapacket import TeaPacket, CtrlType
from teacrypto import TeaAESCipher

taes = TeaAESCipher.newsalt("password".encode("utf8"))


# byt = TeaPacket.text("abc")
byt1 = TeaPacket.keyreq("abc")
print(byt1)
enc = taes.encrypt(byt1)
byt2 = TeaPacket.encrypt(enc.hex())
print(byt2)

tpk = TeaPacket.parse(byt2.decode("utf8"))
byt3 = taes.decrypt(bytes.fromhex(tpk.content))
print(byt3)
tpk2 = TeaPacket.parse(byt3.decode("utf8"))
print(tpk2)
# print(tpk)
