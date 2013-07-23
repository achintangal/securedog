"""
RSA encryption 2048

json protocol:

recv -- "req_type" : "pubkey"
send -- "pubkey" : filestring

recv -- "req_type" : "message"
        "message" : string
        "signature": string
send -- "OK"
"""
import SocketServer
import json
import sys
import base64
import threading
import signal

from pubsub import pub
from Crypto.PublicKey import RSA

privatekey = sys.argv[1]
port = sys.argv[2]
port = int(port)
pubkey = privatekey + ".pub"
pubkey_text = open(pubkey).read()
privatekey_text = open(privatekey).read()
RSA_pubkey = RSA.importKey(pubkey_text)
RSA_privatekey = RSA.importKey(privatekey_text)


def listener_for_msg(arg, request):
    data = arg
    enc_msg = data["message"]
#    sig = data["signature"]
    msg = RSA_privatekey.decrypt(base64.b64decode(enc_msg))
    print msg
    request.sendall("OK")


def listener_for_pubkey(arg, request):
    global pubkey_text
    request.sendall(json.dumps({"pubkey": pubkey_text}))


def listener_for_new(arg, request):
    data = arg
    if data.get('req_type', "") == "pubkey":
        pub.sendMessage("pubkey", arg=data, request=request)
    elif data.get('req_type', "") == "message":
        pub.sendMessage("message", arg=data, request=request)
    elif data.get('req_type', "") == "echo":
        pub.sendMessage("echo", arg=data, request=request)
    else:
        request.sendall(json.dumps({"status": "OK"}))


pub.subscribe(listener_for_new, 'new')
pub.subscribe(listener_for_pubkey, 'pubkey')
pub.subscribe(listener_for_msg, 'message')


class RequestHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        total_data = []
        while True:
            data = self.request.recv(1500)
            if not data:
                break
            total_data.append(data)
        data = ''.join(total_data)
        pub.sendMessage("new", arg=json.loads(data), request=self.request)


server = SocketServer.TCPServer(('127.0.0.1', port), RequestHandler, False)  # Do not automatically bind
server.allow_reuse_address = True # Prevent 'cannot bind to address' errors on restart
server.server_bind()     # Manually bind, to support allow_reuse_address
server.server_activate() # (see above comment)

print "Server Started"
t = threading.Thread(target=server.serve_forever)
t.start()


def signal_handler(signal, frame):
    print "Shutdown"
    server.socket.close()
    server.shutdown()
    exit(0)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGABRT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


from PyQt4 import QtGui as qt
from securedog import QtSecureDog

app = qt.QApplication([])
main_app = QtSecureDog(port)
main_app.show()
app.exec_()

print "Shutdown"
server.socket.close()
server.shutdown()
exit(1)
