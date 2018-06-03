from sulley import *
from tlslite.tlsconnection import *
from tlslite.utils.codec import Parser, Writer
import random
import datetime
import time


def change(value):
    parsed = value
    parsed = parsed.replace(" ", "")
    parsed = parsed.replace("\t", "")
    parsed = parsed.replace("\r", "")
    parsed = parsed.replace("\n", "")
    parsed = parsed.replace(",", "")
    parsed = parsed.replace("0x", "")
    parsed = parsed.replace("\\x", "")

    value = ""
    while parsed:
        pair = parsed[:2]
        parsed = parsed[2:]

        value += chr(int(pair, 16))
    return value


def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ch).replace('0x', '')
        if len(hv) == 1:
            hv = '0' + hv
        lst.append(hv)

    return reduce(lambda x, y: x + y, lst)


def toHex2(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0' + hv
        lst.append(hv)

    return reduce(lambda x, y: x + y, lst)


currentTime = int(time.mktime(datetime.datetime.now().timetuple()))
str = ""
for i in range(1, 29):
    temp = random.randint(0, 255)
    if temp >= 16:
        str = str + hex(temp)
    else:
        str = str + "0x0" + hex(temp)[2]

s_initialize("Client Hello")
s_binary("0x16")
s_binary("0x0300")
s_size("Handshake Client Hello", endian='>', length=2)
if s_block_start("Handshake Client Hello"):
    s_binary("0x01")
    s_size("Cipher Compression", endian='>', length=3)
    if s_block_start("Cipher Compression"):
        s_binary("0x0300", name="Version2")
        s_int(currentTime, name="time", endian='>', fuzzable=False)
        s_binary(str, name="random")
        s_binary("0x00")
 #       s_size("Session ID", endian='>', length=1)
 #       if s_block_start("Session ID"):
 #           s_binary("0x123456789")
 #       s_block_end()
        s_size("Cipher Suites", endian='>', length=2)
        if s_block_start("Cipher Suites"):
            s_binary("0x00ff")
            s_short(5, endian='>', fuzzable=False)
        s_block_end()
        s_binary("0x01", name="Compression Method Length")
        s_binary("0x00", name="Compression Method")
        s_binary("0x0006000900020100")
    s_block_end()
s_block_end()

s_initialize("Client Key Exchange")
s_binary("0x16")
s_binary("0x0300")
s_size("Handshake Client Key Exchange", endian='>', length=2)
if s_block_start("Handshake Client Key Exchange"):
    s_binary("0x10")
    s_size("Encrypted PreMaster", endian='>', length=3)
    if s_block_start("Encrypted PreMaster"):
        s_binary(
            "0x12356789012356789012356789012356789012356789012356789012356789012356789012356789012356789012356789012356789012345678",
            name="PreMaster")
    s_block_end()

s_block_end()

s_initialize("Change Cipher Spec")
s_binary("0x14")
s_binary("0x0300")
s_size("Handshake Change Cipher Spec", endian='>', length=2)
if s_block_start("Handshake Change Cipher Spec"):
    s_binary("0x01")
s_block_end()

s_initialize("Client Finished")
s_binary("0x16")
s_binary("0x0300")
s_size("Handshake Encrypted Handshake Message", endian='>', length=2)
if s_block_start("Handshake Encrypted Handshake Message"):
    s_string("123567890123567890123567890123567890123567890123456", fuzzable=False, name="finshed Message")
s_block_end()

s_initialize("Application Data")
s_binary("0x17")
s_binary("0x0300")
s_size("Encrypted Application Data", endian='>', length=2)
if s_block_start("Encrypted Application Data"):
    s_random("123567890123567890123567890123567890123567890123456", 26, 100, 10)
s_block_end()

tls = None
tlsConnection = None
clientHello = ClientHello()
# all handshake message hash
cipherSuite = None
masterSecret = None
premasterSecret = None
serverHello = None
# TODO
settings = HandshakeSettings()
settings.minVersion = (3, 0)
settings.maxVersion = (3, 0)
settings.cipherNames = ["rc4"]
del settings.keyExchangeNames[2]
settings.useEncryptThenMAC = False
settings.usePaddingExtension = False
settings.useExtendedMasterSecret = False


def getClientHello(session, node, edge, sock):
    global  clientHello, settings, cipherSuite,tls

    tls = TLSConnection(sock)
    randomData = s_get("Client Hello").render()
    b = bytearray()
    b.extend(randomData)
    c = b[6:]
    p = Parser(c)
    clientHello.parse(p)

    result=None
    buf=clientHello.write()
    tls._handshake_hash.update(buf)




def exchange(session, node, edge, sock):
    global tls,settings,clientHello,serverHello,cipherSuite,premasterSecret

    getClientHello(session,node,edge,sock)

    for result in tls._getMsg(ContentType.handshake, HandshakeType.server_hello):
        if result in (0, 1):
            print "erssdsad"
        else:
            break
    serverHello = result
    for result in tls._getMsg(ContentType.handshake, HandshakeType.certificate, CertificateType.x509):
        if result in (0, 1):
            print "erssdsad"
        else:
            break
    certificate_new = result
    for result in tls._getMsg(ContentType.handshake, HandshakeType.server_hello_done):
        if result in (0, 1):
            print "erssdsad"
        else:
            break
    server_hello_done_new = result
    cipherSuite = serverHello.cipher_suite
    tls.version = serverHello.server_version

    keyExchange = RSAKeyExchange(cipherSuite, clientHello, serverHello, None)

    for result in tls._clientGetKeyFromChain(certificate_new, settings):
        if result in (0, 1):
            print "ssss"
        else:
            break
    publicKey, serverCertChain, tackExt = result
    premasterSecret = keyExchange.processServerKeyExchange(publicKey, None)
    clientKeyExchange = keyExchange.makeClientKeyExchange()
    node.names["PreMaster"].value = change(toHex(clientKeyExchange.encryptedPreMasterSecret))

    clientKeyExchangeMesage = node.render()
    b = bytearray()
    b.extend(clientKeyExchangeMesage)
    tls._handshake_hash.update(b[5:])


def finished(session, node, edge, sock):
    global tls, serverHello, cipherSuite,  premasterSecret, settings, clientHello,masterSecret
    tls.version = serverHello.server_version



    changeCipherSpecMesaage = change("0x1403000101")
    b = bytearray()
    b.extend(changeCipherSpecMesaage)
    tls._handshake_hash.update(b[5:])



    masterSecret = calcMasterSecret(clientHello.client_version, cipherSuite, premasterSecret, clientHello.random,
                                    serverHello.random)


    tls._calcPendingStates(cipherSuite, masterSecret, clientHello.random, serverHello.random,
                           settings.cipherImplementations)
    # Switch to pending write state
    tls._changeWriteState()
    # Calculate verification data
    verifyData = calcFinished(clientHello.client_version, masterSecret, cipherSuite, tls._handshake_hash, True)
    finished = Finished(serverHello.server_version).create(verifyData)

    buf=finished.write()
    tls._handshake_hash.update(buf)
    buf = tls._recordLayer._macThenEncrypt(buf, ContentType.handshake)

    node.names["finshed Message"].value = change(toHex(buf))
    try:
        session.last_recv = sock.recv(10000)
    except Exception, e:
        session.last_recv = ""
    tls._recordLayer.shutdown()

sess = sessions.session(session_filename="audit/ssl.session")
target = sessions.target("192.168.1.215", 443)
target.netmon = pedrpc.client("192.168.1.215", 26001)
target.procmon = pedrpc.client("192.168.1.215", 26002)
target.procmon_options = {
    "proc_name": "openssl.exe",
    "stop_commands": ['taskkill /f /t /im openssl.exe'],
    # "start_commands" : ['C:\\Users\\eleanor\\Desktop\\slimftp3.15b\\SlimFTPd.exe'],
    "start_commands": [
     'C:\\OpenSSL\\bin\\openssl.exe s_server -cert C:\\OpenSSL\\bin\\server.crt -key  C:\\OpenSSL\\bin\\server.key -accept 443'],
}

sess.add_target(target)
sess.connect(s_get("Client Hello"))
sess.connect(s_get("Client Hello"), s_get("Client Key Exchange"), exchange)
sess.connect(s_get("Client Key Exchange"), s_get("Change Cipher Spec"))
sess.connect(s_get("Change Cipher Spec"), s_get("Client Finished"), finished)
sess.connect(s_get("Client Finished"), s_get("Application Data"))
sess.fuzz()
