from sulley import *

s_initialize("user")
s_static("USER")
s_delim(" ")
s_static("xzp")
s_static("\r\n")
s_initialize("pass")
s_static("PASS")
s_delim(" ")
s_static("123")
s_static("\r\n")
s_initialize("cwd")
s_static("CWD")
s_delim(" ")
s_string("fuzz")
s_static("\r\n")
s_initialize("dele")
s_static("DELE")
s_delim(" ")
s_string("fuzz")
s_static("\r\n")
s_initialize("mdtm")
s_static("MDTM")
s_delim(" ")
s_string("fuzz")
s_static("\r\n")
s_initialize("mkd")
s_static("MKD")
s_delim(" ")
s_string("fuzz")
s_static("\r\n")


def receive_ftp_banner(sock):
    sock.recv(1024)
sess = sessions.session(session_filename="audit/warftpd.session")
target = sessions.target("192.168.1.110", 21)

target.netmon  = pedrpc.client("192.168.1.215", 26001)
target.procmon = pedrpc.client("192.168.1.215", 26002)
target.procmon_options =  {
	"proc_name"      : "ftpbasicsvr.exe",
	"stop_commands"  : ['taskkill /f /t /im ftpbasicsvr.exe'],
	#"start_commands" : ['C:\\Users\\eleanor\\Desktop\\slimftp3.15b\\SlimFTPd.exe'],
    "start_commands" : ['C:\\Peach\\protocol\\ftp\\easyftp-server-1.7.0.11-en\\ftpbasicsvr.exe /nontservice'],
}
# Here we tie in the receive_ftp_banner function which receives
# a socket.socket() object from Sulley as its only parameter

sess.pre_send = receive_ftp_banner
sess.add_target(target)
sess.connect(s_get("user"))
sess.connect(s_get("user"), s_get("pass"))
sess.connect(s_get("pass"), s_get("mkd"))
sess.connect(s_get("pass"), s_get("cwd")) 
sess.connect(s_get("pass"), s_get("dele"))
sess.connect(s_get("pass"), s_get("mdtm"))
sess.fuzz()