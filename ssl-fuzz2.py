from sulley import *
import time
import random
import datetime
import time

currentTime=int(time.mktime(datetime.datetime.now().timetuple()))
str=""
for i in range(1,29):
   str=str+hex(random.randint(0,256))

s_initialize("Client Hello")
s_binary("0x16",name="Handshake")
s_binary("0x0300",name="Version1")
s_size("Handshake Client Hello",endian='>',length=2)
if s_block_start("Handshake Client Hello"):
	s_binary("0x01",name="Handshake Type")
	s_size("Cipher Compression",endian='>',length=3)
	if s_block_start("Cipher Compression"):
	   s_binary("0x0300",name="Version2")
	   s_int(currentTime,name="time",endian='>',fuzzable=False)
	   s_binary(str,name="random")
	   s_size("Session ID",endian='>',length=1)
	   if s_block_start("Session ID"):
	     s_random("123567890123567890123567890123567890123567890123567890123567890123567890123567890123567890123567890123567890123567890123567890123567890123456",155,255,1000000)
	   s_block_end()
	   s_size("Cipher Suites",endian='>',length=2)
	   if s_block_start("Cipher Suites"):
	     s_short(3,endian='>',fuzzable=False)
	     s_short(4,endian='>',fuzzable=False)
	   s_block_end()
	   s_binary("0x01",name="Compression Method Length")
	   s_binary("0x00",name="Compression Method")
	s_block_end()
s_block_end()

sess = sessions.session(session_filename="audit/ssl2.session")
target = sessions.target("192.168.1.215", 443)
target.netmon  = pedrpc.client("192.168.1.215", 26003)
target.procmon = pedrpc.client("192.168.1.215", 26004)
target.procmon_options =  {
	"proc_name"      : "openssl.exe",
	"stop_commands"  : ['taskkill /f /t /im openssl.exe'],
	#"start_commands" : ['C:\\Users\\eleanor\\Desktop\\slimftp3.15b\\SlimFTPd.exe'],
    "start_commands" : ['C:\\OpenSSL\\bin\\openssl.exe s_server -cert C:\\OpenSSL\\bin\\server.crt -key  C:\\OpenSSL\\bin\\server.key -accept 443'],
}
sess.add_target(target)
sess.connect(s_get("Client Hello"))
sess.fuzz()